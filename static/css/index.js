document.addEventListener("DOMContentLoaded", function () {
    console.log("DOM fully loaded and parsed");
    loadCourses(); // Load courses when the page loads
});

// Function to load courses from the backend
function loadCourses(filterType = 'all') {
    console.log(`Loading courses with filter: ${filterType}`);

    const userId = getUserId(); // Get the logged-in user's ID

    // Fetch courses with progress data for the user
    fetch(`/api/courses?user_id=${userId}`) // Pass user_id as a query parameter
        .then(response => {
            if (!response.ok) {
                throw new Error("Failed to fetch courses");
            }
            return response.json();
        })
        .then(courses => {
            console.log("Courses API Response:", courses); // Debugging log
            displayCourses(courses, filterType); // Display courses with progress data
        })
        .catch(error => {
            console.error("Error fetching courses:", error);
            const coursesGrid = document.getElementById("coursesGrid");
            coursesGrid.innerHTML = `<div class="error-message">Failed to load courses. Please try again later.</div>`;
        });
}

// Function to display courses in the coursesGrid
function displayCourses(courses, filterType) {
    const coursesGrid = document.getElementById("coursesGrid");
    coursesGrid.innerHTML = ""; // Clear existing content

    if (!courses.length) {
        coursesGrid.innerHTML = `<div class="empty-message">No courses found.</div>`;
        return;
    }

    // Populate the coursesGrid with course cards
    courses.forEach(course => {
        const progress = parseFloat(course.progress) || 0; // Parse progress as a number
        const isCompleted = progress === 100; // Courses with 100% progress are considered completed
        const isEnrolled = course.status === "enrolled" || course.status === "completed";

        console.log(`Course ID: ${course.id}, Progress: ${progress}%, Status: ${course.status}`); // Debugging log

        // Apply filter
        if (filterType === 'enrolled' && !isEnrolled) return; // Skip if not enrolled
        if (filterType === 'completed' && (!isEnrolled || !isCompleted)) return; // Skip if not enrolled or not 100% completed

        const card = document.createElement("div");
        card.classList.add("course-card");
        card.innerHTML = `
            <!-- Circular Progress Bar in Top-Right Corner -->
            <div class="circular-progress" data-progress="${progress}" style="--progress: ${progress}%;"></div>
            
            <!-- Course Image -->
            <img src="${course.images}" alt="${course.title}" class="course-image" onerror="this.onerror=null; this.src='/static/images/default.jpg';">
            
            <!-- Course Title and Info -->
            <h3 class="course-title">${course.title}</h3>
            <p class="course-info">
                <strong>Duration:</strong> ${course.duration} weeks<br>
                <strong>Instructor ID:</strong> ${course.instructor_id}
            </p>
            
            <!-- Buttons -->
            <div class="button-container">
                <button class="enroll-btn ${isEnrolled ? 'disabled' : ''}" onclick="${isEnrolled ? '' : `enrollCourse(${course.id})`}" ${isEnrolled ? 'disabled' : ''}>
                    <i class="fas fa-sign-in-alt"></i> ${isEnrolled ? (isCompleted ? "Completed" : "Enrolled") : "Enroll Now"}
                </button>
                ${isEnrolled ? `
                    <button class="view-course-btn" onclick="viewCourseModules(${course.id})">
                        <i class="fas fa-list"></i> View Course
                    </button>
                ` : ''}
            </div>
        `;

        // Add click event to the course card
        card.addEventListener("click", () => {
            window.location.href = `/course/${course.id}`; // Redirect to course details page
        });

        coursesGrid.appendChild(card);
    });
}
//Function to handle course enrollment
function enrollCourse(courseId) {
    const userId = getUserId(); // Get the logged-in user's ID
    console.log(`Enrolling user ${userId} in course ${courseId}`);

    fetch('/api/enroll', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            user_id: userId,
            course_id: courseId
        }),
    })
    .then(response => {
        if (!response.ok) {
            throw new Error("Failed to enroll in course");
        }
        return response.json();
    })
    .then(data => {
        console.log("Enrollment API Response:", data); // Debugging log
        alert(data.message); // Show success message
        loadCourses(); // Reload courses after enrollment
    })
    .catch(error => {
        console.error("Error enrolling in course:", error);
        alert("Failed to enroll in course. Please try again.");
    });
}

// Function to filter courses based on search input
function filterCourses() {
    const searchValue = document.getElementById("searchInput").value.trim().toLowerCase();
    const courseCards = document.querySelectorAll(".course-card");

    courseCards.forEach(card => {
        const title = card.querySelector(".course-title").textContent.toLowerCase();
        if (title.includes(searchValue)) {
            card.style.display = ""; // Show matching courses
        } else {
            card.style.display = "none"; // Hide non-matching courses
        }
    });
}

// Function to apply course filter (all, enrolled, completed)
function applyCourseFilter(filterType) {
    console.log(`Applying filter: ${filterType}`); // Debugging log
    loadCourses(filterType); // Reload courses with the selected filter
}

// Function to view course modules
function viewCourseModules(courseId) {
    fetch(`/api/courses/${courseId}/modules`) // Fetch modules for the selected course
        .then(response => {
            if (!response.ok) {
                throw new Error("Failed to fetch course modules");
            }
            return response.json();
        })
        .then(modules => {
            console.log(modules);
            displayCourseModules(modules); // Display the modules in a modal
        })
        .catch(error => {
            console.error("Error fetching course modules:", error);
            alert("Failed to load course modules. Please try again later.");
        });
}

// Function to display course modules in a modal
function displayCourseModules(modules) {
    const modulesModal = document.createElement("div");
    console.log(modules);
    modulesModal.classList.add("modal");
    modulesModal.innerHTML = `
        <div class="modal-content">
            <h2>Course Modules</h2>
            <div id="modulesList">
                ${modules.length > 0 ? modules.map(module => `
                    <div class="module-item">
                        <h4>${module.title}</h4>
                        <p>${module.content}</p>
                        <p><strong>Duration:</strong> ${module.learning_points}</p>
                    </div>
                `).join("") : "<p>No modules available for this course.</p>"}
            </div>
            <div class="modal-buttons">
                <button class="modal-btn cancel-btn" onclick="closeModulesModal()">Close</button>
            </div>
        </div>
    `;

    document.body.appendChild(modulesModal);
    modulesModal.style.display = "block";
}

// Function to close the modules modal
function closeModulesModal() {
    const modulesModal = document.querySelector(".modal");
    if (modulesModal) {
        modulesModal.remove();
    }
}

// Helper function to get the logged-in user's ID
function getUserId() {
    // Replace this with logic to retrieve the user ID from the session or a global variable
    return 1; // Example: Hardcoded for now
}