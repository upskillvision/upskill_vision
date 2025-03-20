let currentModuleIndex = 0;
let courseModules = []; // Store the fetched modules
let userRating = 0; // Store the user's selected rating

document.addEventListener('DOMContentLoaded', () => {
    // Get the course ID from the URL query parameter
    const urlParams = new URLSearchParams(window.location.search);
    const courseId = urlParams.get('course_id');

    console.log(`Course ID from URL: ${courseId}`); // Debugging log

    // Check if course ID is provided
    if (!courseId) {
        alert('No course selected. Redirecting to homepage...');
        window.location.href = "{{ url_for('index') }}"; // Redirect to the homepage
        return;
    }

    // Fetch modules for the selected course
    fetchCourseModules(courseId);
});

// Fetch modules for the selected course
function fetchCourseModules(courseId) {
    fetch(`/api/course-modules/${courseId}`)
        .then(response => {
            console.log("Fetch response:", response); // Debugging log
            if (!response.ok) {
                throw new Error("Failed to fetch modules");
            }
            return response.json();
        })
        .then(modules => {
            console.log("Fetched modules:", modules); // Debugging log
            if (modules.length === 0) {
                alert('No modules found for this course.');
                return;
            }

            // Store the fetched modules
            courseModules = modules;

            // Update the UI with the first module
            updateUI();
            loadModuleList();
            updateProgressBar(); // Initialize progress bar
        })
        .catch(error => {
            console.error('Error fetching modules:', error);
            alert('Failed to load course modules. Please try again later.');
        });
}

// Update the UI with the current module
function updateUI() {
    const currentModule = courseModules[currentModuleIndex];
    
    // Update module details
    const moduleTitle = document.getElementById('currentModuleTitle');
    const moduleDescription = document.getElementById('currentModuleDescription');

    moduleTitle.textContent = currentModule.title;
    moduleDescription.textContent = currentModule.content || "No description available";

    // Highlight the active module in the list
    loadModuleList();
}

// Load the list of modules in the sidebar
function loadModuleList() {
    const moduleList = document.getElementById('moduleList');
    moduleList.innerHTML = courseModules.map((module, index) => `
        <div class="module-item ${index === currentModuleIndex ? 'active' : ''}" 
             onclick="changeModule(${index})">
            ${module.is_completed ? 
                '<i class="fas fa-check-circle completed"></i>' : 
                '<i class="far fa-circle"></i>'
            }
            <div>
                <div>${module.title}</div>
                <small>${module.learning_points || "No learning points specified"}</small>
            </div>
        </div>
    `).join('');
}

// Change the current module
function changeModule(index) {
    currentModuleIndex = index;
    updateUI();
}

// Mark the current module as complete
function markModuleComplete() {
    const moduleId = courseModules[currentModuleIndex].id;

    // Send a request to mark the module as complete
    fetch('/api/mark-module-complete', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ module_id: moduleId }),
    })
        .then(response => {
            if (!response.ok) {
                throw new Error("Failed to mark module as complete");
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Update the UI to reflect the completed module
                courseModules[currentModuleIndex].is_completed = true;
                loadModuleList();
                updateProgressBar(); // Update progress bar after marking module complete

                // Check if all modules are completed
                checkCourseCompletion();
            }
        })
        .catch(error => {
            console.error('Error marking module complete:', error);
            alert('Failed to mark module as complete. Please try again.');
        });
}

// Update the progress bar based on completed modules
function updateProgressBar() {
    const completedModules = courseModules.filter(module => module.is_completed).length;
    const totalModules = courseModules.length;
    const progressPercentage = (completedModules / totalModules) * 100;

    const progressBar = document.getElementById('progressBar');
    progressBar.style.width = `${progressPercentage}%`;

    // Update progress text
    document.getElementById('progressText').textContent = `${progressPercentage.toFixed(0)}% Completed`;
}

// Check if all modules are completed
function checkCourseCompletion() {
    const allCompleted = courseModules.every(module => module.is_completed);
    
    // If all modules are completed, show the rating section
    if (allCompleted) {
        document.getElementById('courseRatingContainer').style.display = 'block';
        initializeRatingSystem();
    }
}

// Initialize the rating system
function initializeRatingSystem() {
    const stars = document.querySelectorAll('.rating-star');
    
    stars.forEach(star => {
        star.addEventListener('click', function() {
            const rating = parseInt(this.getAttribute('data-rating'));
            userRating = rating;
            
            stars.forEach(s => {
                s.classList.remove('active');
                s.classList.remove('fas');
                s.classList.add('far');
            });
            
            for (let i = 0; i < rating; i++) {
                stars[i].classList.remove('far');
                stars[i].classList.add('fas');
                stars[i].classList.add('active');
            }
            
            updateRatingText(rating);
        });
        
        star.addEventListener('mouseover', function() {
            const rating = parseInt(this.getAttribute('data-rating'));
            
            for (let i = 0; i < rating; i++) {
                stars[i].classList.remove('far');
                stars[i].classList.add('fas');
            }
        });
        
        star.addEventListener('mouseout', function() {
            stars.forEach((s, index) => {
                if (index < userRating) {
                    s.classList.remove('far');
                    s.classList.add('fas');
                } else {
                    s.classList.remove('fas');
                    s.classList.add('far');
                }
            });
        });
    });
    
    document.getElementById('submitRating').addEventListener('click', function() {
        if (userRating > 0) {
            submitUserRating(userRating);
        } else {
            alert('Please select a rating before submitting');
        }
    });
}

// Update the rating text
function updateRatingText(rating) {
    const ratingTexts = [
        "Select your rating",
        "Poor - Needs improvement",
        "Fair - Below average",
        "Good - Average quality",
        "Very good - Above average",
        "Excellent - Outstanding"
    ];
    
    document.getElementById('ratingText').textContent = ratingTexts[rating];
}

// Submit the user's rating
function submitUserRating(rating) {
    const urlParams = new URLSearchParams(window.location.search);
    const courseId = urlParams.get('course_id');

    // Send the rating to the backend
    fetch('/api/submit-rating', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
            course_id: courseId, 
            rating: rating
        }),
    })
        .then(response => {
            if (!response.ok) {
                throw new Error("Failed to submit rating");
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Show thank you message and hide the submit button
                document.getElementById('submitRating').style.display = 'none';
                document.getElementById('thankYouMessage').style.display = 'block';
            }
        })
        .catch(error => {
            console.error('Error submitting rating:', error);
            alert('Failed to submit rating. Please try again.');
        });
}