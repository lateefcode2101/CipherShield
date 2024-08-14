// Enhanced script.js

document.addEventListener('DOMContentLoaded', function() {
    const registerForm = document.querySelector('form[action="/register"]');
    const loginForm = document.querySelector('form[action="/login"]');
    const uploadForm = document.querySelector('form[action="/upload"]');

    if (registerForm) {
        registerForm.addEventListener('submit', function(event) {
            const username = registerForm.querySelector('input[name="username"]').value;
            const email = registerForm.querySelector('input[name="email"]').value;
            const password = registerForm.querySelector('input[name="password"]').value;

            let errorMessage = "";
            if (!username) errorMessage += "Username is required.\n";
            if (!email) errorMessage += "Email is required.\n";
            if (!password) errorMessage += "Password is required.";

            if (errorMessage) {
                event.preventDefault();
                displayError(registerForm, errorMessage.trim());
            }
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', function(event) {
            const username = loginForm.querySelector('input[name="username"]').value;
            const password = loginForm.querySelector('input[name="password"]').value;

            let errorMessage = "";
            if (!username) errorMessage += "Username is required.\n";
            if (!password) errorMessage += "Password is required.";

            if (errorMessage) {
                event.preventDefault();
                displayError(loginForm, errorMessage.trim());
            }
        });
    }

    if (uploadForm) {
        uploadForm.addEventListener('submit', (event) => {
            const uuid = document.getElementById('uuid').value;
            const title = uploadForm.querySelector('input[name="title"]').value;
            const description = uploadForm.querySelector('textarea[name="description"]').value;

            const regex = /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i;

            let errorMessage = "";
            if (!regex.test(uuid)) errorMessage += "Invalid UUID format.\n";
            if (!title) errorMessage += "Title is required.\n";
            if (!description) errorMessage += "Description is required.";

            if (errorMessage) {
                event.preventDefault();
                displayError(uploadForm, errorMessage.trim());
            } else {
                displaySuccess(uploadForm, "Valid data submitted!");
            }
        });
    }

    function displayError(form, message) {
        let errorElement = form.querySelector('.error-message');
        if (!errorElement) {
            errorElement = document.createElement('div');
            errorElement.className = 'error-message';
            form.prepend(errorElement);
        }
        errorElement.textContent = message;
    }

    function displaySuccess(form, message) {
        let successElement = form.querySelector('.success-message');
        if (!successElement) {
            successElement = document.createElement('div');
            successElement.className = 'success-message';
            form.prepend(successElement);
        }
        successElement.textContent = message;
    }
});
