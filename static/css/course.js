// Ensure the DOM is fully loaded before executing scripts
document.addEventListener('DOMContentLoaded', function () {
    // Check if we're on the course details page
    const modulesContainer = document.getElementById('modules-container');

    if (modulesContainer) {
        // If modules container exists, we're on the course details page
        fetchAndDisplayModules();
    } else {
        // If modules container doesn't exist, we're on the courses listing page
        initializeCourseCards();
    }
});

// ========================
// Course Details Page Logic
// ========================

async function fetchAndDisplayModules() {
    const modulesContainer = document.getElementById('modules-container');

    if (!modulesContainer) {
        console.error('Modules container not found');
        return;
    }

    // Get the course ID from the data attribute
    const courseId = modulesContainer.dataset.courseId;

    if (!courseId) {
        console.error('Course ID not found in data attribute');
        modulesContainer.innerHTML = '<p>Error: Course information missing</p>';
        return;
    }

    try {
        // Show loading state
        modulesContainer.innerHTML = '<p>Loading modules...</p>';

        // Fetch modules for the selected course
        const response = await fetch(`/api/courses/${courseId}/modules`);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const modules = await response.json();
        displayModules(modules);

    } catch (error) {
        console.error('Error fetching modules:', error);
        modulesContainer.innerHTML = `
            <p class="error-message">
                Error loading modules. Please try again later.<br>
                <small>${error.message}</small>
            </p>
        `;
    }
}

function displayModules(modules) {
    const container = document.getElementById('modules-container');

    if (!modules || modules.length === 0) {
        container.innerHTML = '<p>No modules available for this course yet.</p>';
        return;
    }

    // Generate HTML for modules with radio buttons
    const html = modules.map(module => `
        <div class="module">
            <label>
                <input type="radio" name="module" value="${module.id}" class="radio-button" onchange="loadModuleContent(${module.id})">
                <h3>${module.title}</h3>
                <p>${module.description}</p>
                <div class="module-meta">
                    <span class="status ${module.is_completed ? 'completed' : 'in-progress'}">
                        ${module.is_completed ? '✓ Completed' : '● In Progress'}
                    </span>
                </div>
            </label>
        </div>
    `).join('');

    // Insert modules into the container
    container.innerHTML = html;
}

// Function to load module content when a radio button is selected
async function loadModuleContent(moduleId) {
    try {
        const response = await fetch(`/api/modules/${moduleId}`);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const module = await response.json();

        // Display module content
        const moduleContentSection = document.getElementById('module-content');
        moduleContentSection.style.display = 'block';

        document.getElementById('module-content-title').textContent = module.title;
        document.getElementById('module-content-description').textContent = module.description;
        document.getElementById('module-content-status').textContent = module.is_completed ? 'Completed' : 'Not Completed';
        document.getElementById('module-content-body').innerHTML = module.content || 'No content available.';

    } catch (error) {
        console.error('Error loading module content:', error);
        const moduleContentSection = document.getElementById('module-content');
        moduleContentSection.innerHTML = `
            <p class="error-message">
                Error loading module content. Please try again later.<br>
                <small>${error.message}</small>
            </p>
        `;
    }
}

// ========================
// Course Listing Page Logic
// ========================

function initializeCourseCards() {
    const coursesContainer = document.getElementById('courses-container');

    if (!coursesContainer) {
        console.error('Courses container not found');
        return;
    }

    // Fetch and display courses
    fetchAndDisplayCourses();
}

async function fetchAndDisplayCourses() {
    try {
        const response = await fetch('/api/courses');

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const courses = await response.json();
        renderCourseCards(courses);

    } catch (error) {
        console.error('Error fetching courses:', error);
        const container = document.getElementById('courses-container');
        if (container) {
            container.innerHTML = `
                <p class="error-message">
                    Error loading courses. Please try again later.<br>
                    <small>${error.message}</small>
                </p>
            `;
        }
    }
}

function renderCourseCards(courses) {
    const container = document.getElementById('courses-container');

    if (!container) {
        console.error('Courses container not found');
        return;
    }

    if (!courses || courses.length === 0) {
        container.innerHTML = '<p>No courses available yet.</p>';
        return;
    }

    // Clear existing content
    container.innerHTML = '';

    // Create and append course cards
    courses.forEach(course => {
        const courseCard = createCourseCard(course);
        container.appendChild(courseCard);
    });
}

function createCourseCard(course) {
    const courseCard = document.createElement('div');
    courseCard.className = 'course-card';
    courseCard.innerHTML = `
        <div class="course-image">
            <img src="${course.images}" 
                 alt="${course.title}"
                 onerror="this.onerror=null; this.src='/static/images/default.jpg';">
        </div>
        <div class="course-content">
            <h3 class="course-title">${course.title}</h3>
            <p class="course-description">${course.description}</p>
            <div class="course-meta">
                <span class="duration">⏱ ${course.duration} hours</span>
                <span class="status ${course.status.toLowerCase()}">${course.status}</span>
            </div>
            <div class="progress-container">
                <div class="progress-bar" style="width: ${course.progress}%;"></div>
            </div>
        </div>
    `;

    // Add click handler to redirect to the course details page
    courseCard.addEventListener('click', () => {
        window.location.href = `/course/${course.id}`;
    });

    return courseCard;
}