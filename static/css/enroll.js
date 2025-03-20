document.addEventListener("DOMContentLoaded", function () {
    const userId = 1; // Replace with dynamic user ID (e.g., from localStorage or session)
    loadEnrolledCourses(userId);
});

// Function to load enrolled courses
function loadEnrolledCourses(userId) {
    fetch(`/api/enrolled-courses/${userId}`) // Use relative path
        .then(response => {
            if (!response.ok) {
                throw new Error("Failed to fetch enrolled courses");
            }
            return response.json();
        })
        .then(courses => {
            updateEnrolledCoursesUI(courses);
        })
        .catch(error => {
            console.error("Error fetching enrolled courses:", error);
            const enrolledCoursesContainer = document.getElementById("enrolled-courses");
            enrolledCoursesContainer.innerHTML = `<div class="error-message">Failed to load enrolled courses. Please try again later.</div>`;
        });
}

// Function to update the UI with enrolled courses
function updateEnrolledCoursesUI(courses) {
    const enrolledCoursesContainer = document.getElementById("enrolled-courses");

    enrolledCoursesContainer.innerHTML = "";

    if (!courses.length) {
        enrolledCoursesContainer.innerHTML = `<div class="empty-message">You are not enrolled in any courses. <a href="{{ url_for('index') }}">Browse courses</a>.</div>`;
        return;
    }

    // Populate enrolled courses
    courses.forEach(course => {
        const card = document.createElement("div");
        card.classList.add("course-card");
        card.innerHTML = `
            <img src="${course.images}" alt="${course.title}" class="course-image">
            <h3 class="course-title">${course.title}</h3>
            <p class="course-info">
                <strong>Duration:</strong> ${course.duration} weeks<br>
                <strong>Instructor ID:</strong> ${course.instructor_id}
            </p>
            <div class="progress-container">
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${course.progress}%"></div>
                </div>
                <p class="progress-text">${course.progress}% Completed</p>
            </div>
            <button class="view-btn" onclick="viewCourse(${course.id})">
                <i class="fas fa-eye"></i> ${course.progress === 100 ? "Review Course" : "Continue Learning"}
            </button>
            <button class="view-modules-btn" onclick="viewCourseModules(${course.id})">
                <i class="fas fa-list"></i> View Modules
            </button>
        `;

        // Add click event to the course card
        card.addEventListener("click", () => {
            window.location.href = `/course/${course.id}`;
        });

        enrolledCoursesContainer.appendChild(card);
    });
}

// Function to view a course (redirect to learning page)
function viewCourse(courseId) {
    localStorage.setItem("currentCourseId", courseId);
    window.location.href = "{{ url_for('learning') }}"; // Use Flask's url_for for redirection
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
            displayCourseModules(modules);
        })
        .catch(error => {
            console.error("Error fetching course modules:", error);
            alert("Failed to load course modules. Please try again later.");
        });
}

// Function to display course modules in a modal
function displayCourseModules(modules) {
    const modulesModal = document.createElement("div");
    modulesModal.classList.add("modal");
    modulesModal.innerHTML = `
        <div class="modal-content">
            <h2>Course Modules</h2>
            <div id="modulesList">
                ${modules.length > 0 ? modules.map(module => `
                    <div class="module-item">
                        <h4>${module.title}</h4>
                        <p>${module.description}</p>
                        <p><strong>Duration:</strong> ${module.duration}</p>
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