// Current quiz state (if needed for other functionality)
let currentQuiz = {
    course: '',
    questions: [],
    userAnswers: [], // Stores the user's selected answers (index of the selected option)
    score: 0
};

// Initialize the page
document.addEventListener("DOMContentLoaded", function () {
    loadEnrolledCourses(); // Load enrolled courses when the page loads

    // Set up exit quiz button event (if applicable)
    const exitQuizBtn = document.getElementById("exit-quiz-btn");
    if (exitQuizBtn) {
        exitQuizBtn.addEventListener("click", function () {
            document.getElementById("exit-confirmation-modal").classList.remove("hidden");
        });
    }
});

// Get User ID
function getUserId() {
    // Replace this with logic to retrieve the user ID from the session or a global variable
    return 1; // Example: Hardcoded for now
}

// Load enrolled courses and display them as cards
function loadEnrolledCourses() {
    const userId = getUserId();
    const courseCardsContainer = document.getElementById("course-cards");
    courseCardsContainer.innerHTML = '<p>Loading enrolled courses...</p>';

    fetch(`/api/enrolled-courses/${userId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error("Failed to fetch enrolled courses");
            }
            return response.json();
        })
        .then(courses => {
            courseCardsContainer.innerHTML = ""; // Clear loading message
            if (courses.length === 0) {
                courseCardsContainer.innerHTML = '<p>No enrolled courses found.</p>';
                return;
            }

            courses.forEach(course => {
                const courseCard = document.createElement("div");
                courseCard.className = "course-card";
                courseCard.innerHTML = `
                    <h3>${course.title}</h3>
                    <p>${course.description || "No description available"}</p>
                    <div class="progress-container">
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${course.progress || 0}%;"></div>
                        </div>
                        <p class="progress-text">${course.progress || 0}% Completed</p>
                    </div>
                `;

                // Redirect to the course details page with the course_id as a path parameter
                courseCard.addEventListener("click", () => {
                    window.location.href = `/course/${course.id}`;
                });

                courseCardsContainer.appendChild(courseCard);
            });
        })
        .catch(error => {
            console.error("Error loading enrolled courses:", error);
            courseCardsContainer.innerHTML = '<p>Error loading courses. Please try again later.</p>';
        });
}

// Start quiz for the selected course (if needed for other functionality)
function startQuiz(courseId, courseTitle) {
    console.log(`Starting quiz for course ID: ${courseId}`); // Debugging log

    // Set up current quiz
    currentQuiz.course = courseId;

    // Fetch quiz questions
    fetch(`/api/quizzes/${courseId}`)
        .then(response => {
            console.log("Fetch response:", response); // Debugging log
            if (!response.ok) {
                throw new Error(`Failed to fetch quiz questions. Status: ${response.status}`);
            }
            return response.json();
        })
        .then(questions => {
            console.log("Quiz Questions:", questions); // Debugging log
            if (!questions || questions.length === 0) {
                throw new Error("No quiz questions found for this course");
            }

            // Validate the structure of each question
            questions.forEach((question, index) => {
                if (!question.question_text || !question.options || !question.correct_answer) {
                    throw new Error(`Invalid question structure at index ${index}`);
                }
            });

            currentQuiz.questions = questions;
            currentQuiz.userAnswers = new Array(currentQuiz.questions.length).fill(-1); // Initialize user answers
            currentQuiz.score = 0;

            // Hide quiz page, show quiz questions
            document.getElementById("quiz-page").classList.add("hidden");
            document.getElementById("quiz-questions").classList.remove("hidden");

            // Set quiz title
            document.getElementById("quiz-title").textContent = `${courseTitle} Quiz`;

            // Load questions
            loadQuestions();
        })
        .catch(error => {
            console.error("Error loading quiz questions:", error); // Debugging log
            alert("Error loading quiz questions. Please try again later.");
        });
}

// Load questions (if needed for other functionality)
function loadQuestions() {
    const questionContainer = document.getElementById("question-container");
    questionContainer.innerHTML = ""; // Clear existing content

    // Create questions and options
    currentQuiz.questions.forEach((q, qIndex) => {
        const questionElement = document.createElement("div");
        questionElement.className = "quiz-question";

        // Display the question text
        const questionTitle = document.createElement("h3");
        questionTitle.textContent = `Question ${qIndex + 1}: ${q.question_text}`;
        questionElement.appendChild(questionTitle);

        // Parse the options array
        const options = q.options; // No need to parse, as it's already an array

        // Create a container for the options
        const optionsContainer = document.createElement("div");
        optionsContainer.className = "quiz-options";

        // Add each option to the container
        options.forEach((option, oIndex) => {
            const optionElement = document.createElement("div");
            optionElement.className = "quiz-option";
            optionElement.setAttribute("data-question", qIndex);
            optionElement.setAttribute("data-option", oIndex);

            // Display only the option text (e.g., "HyperText Markup Language")
            optionElement.textContent = option.text;

            // Add selected class if this option is already selected
            if (currentQuiz.userAnswers[qIndex] === oIndex) {
                optionElement.classList.add("selected");
            }

            // Add click event to select option
            optionElement.addEventListener("click", function () {
                selectOption(qIndex, oIndex);
            });

            optionsContainer.appendChild(optionElement);
        });

        // Add the options container to the question
        questionElement.appendChild(optionsContainer);

        // Add the question to the main container
        questionContainer.appendChild(questionElement);
    });
}

// Select option (if needed for other functionality)
function selectOption(questionIndex, optionIndex) {
    // Save user answer
    currentQuiz.userAnswers[questionIndex] = optionIndex;

    // Update UI
    const questionOptions = document.querySelectorAll(`.quiz-option[data-question="${questionIndex}"]`);
    questionOptions.forEach(option => {
        option.classList.remove("selected");
    });

    const selectedOption = document.querySelector(`.quiz-option[data-question="${questionIndex}"][data-option="${optionIndex}"]`);
    selectedOption.classList.add("selected");
}

// Submit quiz (if needed for other functionality)
function submitQuiz() {
    // Check if all questions are answered
    if (currentQuiz.userAnswers.includes(-1)) {
        alert("Please answer all questions before submitting");
        return;
    }

    // Calculate the score
    let correctAnswers = 0;
    currentQuiz.questions.forEach((q, index) => {
        const userAnswer = currentQuiz.userAnswers[index];
        const correctAnswer = q.correct_answer;

        // Compare the user's answer with the correct answer
        const options = q.options;
        if (options[userAnswer].id === correctAnswer) {
            correctAnswers++;
        }
    });

    const totalQuestions = currentQuiz.questions.length;
    const scorePercentage = (correctAnswers / totalQuestions) * 100;

    // Display the quiz results
    document.getElementById("quiz-score").textContent = `Score: ${correctAnswers}/${totalQuestions} (${scorePercentage.toFixed(2)}%)`;

    // Show results page
    document.getElementById("quiz-questions").classList.add("hidden");
    document.getElementById("quiz-results").classList.remove("hidden");

    // Update the user's progress in the backend (optional)
    const userId = getUserId();
    const courseId = currentQuiz.course;

    fetch("/api/update-progress", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            user_id: userId,
            course_id: courseId,
            progress: scorePercentage
        })
    })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            console.log("Progress updated successfully:", data);
        })
        .catch(error => {
            console.error("Error updating progress:", error);
        });
}

// Return to quiz page (if needed for other functionality)
function returnToQuizPage() {
    // Show header and sidebar
    document.getElementById("main-header").style.display = "block";
    document.getElementById("sidebar").style.display = "block";

    // Show quiz page, hide results
    document.getElementById("quiz-results").classList.add("hidden");
    document.getElementById("quiz-page").classList.remove("hidden");

    // Reload quiz history (if applicable)
    loadEnrolledCourses();
}

// Confirm exit quiz (if needed for other functionality)
function confirmExitQuiz() {
    document.getElementById("exit-confirmation-modal").classList.add("hidden");

    // Show header and sidebar
    document.getElementById("main-header").style.display = "block";
    document.getElementById("sidebar").style.display = "block";

    // Return to quiz page
    document.getElementById("quiz-questions").classList.add("hidden");
    document.getElementById("quiz-page").classList.remove("hidden");
}