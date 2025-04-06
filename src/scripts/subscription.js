document.addEventListener('DOMContentLoaded', checkQueryParamsAndLoadModal);

function checkQueryParamsAndLoadModal() {
    const urlParams = new URLSearchParams(window.location.search);
    const subPlan = urlParams.get('policyName');
    const apiName = urlParams.get('apiName');
    const apiVersion = urlParams.get('apiVersion');

    if (subPlan && apiName && apiVersion) {
        const modal = document.getElementById('planModal');
        modal.style.display = 'block';

        const planName = document.getElementById('planName');
        planName.innerText = subPlan;
    }
}

async function unsubscribe(subscriptionId) {
    try {
        const response = await fetch(`/devportal/subscriptions/${subscriptionId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (response.ok) {
            await showAlert(`Unsubscribed successfully!`, 'success');
            const url = new URL(window.location.origin + window.location.pathname);
            window.location.href = url.toString();
        } else {
            const responseData = await response.json();
            console.error('Failed to unsubscribe:', responseData);
            await showAlert(`Failed to unsubscribe.\n${responseData.description}`, 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        await showAlert(`An error occurred.\n${error.message}`, 'error');
    }
}

function hideElementById(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.style.display = 'none';
    }
}

function closeModal(elementId) {
    hideElementById(elementId);
    document.querySelector("form").reset();
    document.querySelectorAll('[style*="display: block"]').forEach(element => {
        element.style.display = "none";
    });
}

window.onclick = function (event) {
    const modal = document.getElementById('planModal');
    if (event.target === modal) {
        closeModal();
    }
};

// Function to show the application creation form
function showApplicationForm() {
    const creationForm = document.getElementById('applicationFormCreation');
    creationForm.style.display = 'block';

    hideElementById('applicationFormSection');

    const subButton = document.getElementById('createSubButton');
    subButton.style.display = 'block';
}

// Function to handle application creation
async function handleCreateSubscribe() {
    const urlParams = new URLSearchParams(window.location.search);
    try {
        // Sanitize the application name
        const appName = document.getElementById('appName').value.trim().replace(/[^a-zA-Z0-9\s]/g, '');
        if (!appName) {
            await showAlert('Application name cannot be empty.', 'error');
            return;
        }

        const response = await fetch(`/devportal/applications`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ name: sanitize(appName) }),
        });

        const responseData = await response.json();

        if (response.ok) {
            handleSubscribe(responseData.applicationId);
        } else {
            console.error('Failed to create application:', responseData);
            await showAlert(`Failed to create application. Please try again.\n${responseData.description}`, 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        await showAlert(`An error occurred while subscribing: \n${error.message}`, 'error');
    }
}

function sanitize(input) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(input));
    return div.innerHTML;
}

async function handleSubscribe(appId, apiName, apiVersion, apiRefId) {
    const applicationSelect = document.getElementById('applicationSelect');
    let policyName;

    const applicationId = appId !== null
        ? appId
        : (applicationSelect ? applicationSelect.value : window.location.pathname.split('/').pop());


    if (!applicationId) {
        await showAlert('Please select an application.', 'error');
        return;
    }

    try {
        const urlParams = new URLSearchParams(window.location.search);

        if (urlParams.has('apiName') && urlParams.has('policyName')) {
            apiName = urlParams.get('apiName');
            apiVersion = urlParams.get('apiVersion');
            policyName = urlParams.get('policyName');
        } else {
            policyName = document.getElementById('subscriptionPlan').value;
        }

        const response = await fetch(`/devportal/subscriptions`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                applicationId: applicationId.replace(/[^a-zA-Z0-9\s-]/g, ''),
                apiName: apiName.replace(/[^a-zA-Z0-9\s-]/g, ''),
                apiVersion: apiVersion.replace(/[^a-zA-Z0-9\s-.]/g, ''),
                throttlingPolicy: policyName.replace(/[^a-zA-Z0-9\s-]/g, ''),
                apiRefId: apiRefId,
            }),
        });

        const responseData = await response.json();
        if (response.ok) {
            await showAlert('Subscribed successfully!', 'success');
            const url = new URL(window.location.origin + window.location.pathname);
            window.location.href = url.toString();
        } else {
            console.error('Failed to subscribe:', responseData);
            await showAlert(`Failed to subscribe. Please try again.\n${responseData.description}`, 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        await showAlert(`An error occurred while subscribing: \n${error.message}`, 'error');
    }
}

function loadModal(modalID) {
    const modal = document.getElementById(modalID);
    modal.style.display = 'flex';
}

async function subscribe(orgID, applicationID, apiId, apiReferenceID, policyId, policyName) {
    console.log('Subscribing to API:', apiId);
    
    // Find the related card and button elements
    const card = getSubscriptionCard(apiId, policyId);
    const subscribeButton = card ? card.querySelector(".common-btn-primary") : null;
    const messageOverlay = card ? card.querySelector(".message-overlay") : null;
    
    try {
        // Get application ID from hidden field if not provided
        if (!applicationID && card) {
            const hiddenField = card.querySelector('input[type="hidden"]');
            if (hiddenField && hiddenField.value) {
                applicationID = hiddenField.value;
            }
        }
        
        // Make the API request
        const response = await fetch(`/devportal/organizations/${orgID}/subscriptions`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ applicationID, apiId, apiReferenceID, policyId, policyName }),
        });

        const responseData = await response.json();
        
        // Always reset button state and close modal
        const planButton = document.getElementById('subscribe-btn-' + policyId);
        if (planButton) {
            resetSubscribeButtonState(planButton);
        }
        closeModal('planModal-' + apiId);
        resetSubscribeButtonState(subscribeButton);

        if (response.ok) {
            // Show success notification
            showSubscriptionMessage(messageOverlay, 'Successfully subscribed to API', 'success');
        } else {
            // Handle API error
            console.error('Failed to create subscription:', responseData);
            const errorMessage = `Failed to subscribe: ${responseData.description || 'Unknown error'}`;
            showSubscriptionMessage(messageOverlay, errorMessage, 'error');
        }
    } catch (error) {
        // Handle exceptions
        console.error('Error:', error);
        
        // Always reset button state and close modal
        const planButton = document.getElementById('subscribe-btn-' + policyId);
        if (planButton) {
            resetSubscribeButtonState(planButton);
        }
        closeModal('planModal-' + apiId);
        resetSubscribeButtonState(subscribeButton);
        
        const errorMessage = `Error while subscribing: ${error.message}`;
        showSubscriptionMessage(messageOverlay, errorMessage, 'error');
    }
}

// Helper functions for the subscribe function
function getSubscriptionCard(apiId, policyId) {
    return document.getElementById('apiCard-' + apiId) || 
           document.getElementById('subscriptionCard-' + policyId) || 
           null;
}

function resetSubscribeButtonState(button) {
    if (button && typeof window.resetSubscribeButtonState === 'function') {
        window.resetSubscribeButtonState(button);
    }
}

function showSubscriptionMessage(messageOverlay, message, type) {
    if (messageOverlay && typeof window.showApiMessage === 'function') {
        window.showApiMessage(messageOverlay, message, type);
    } else {
        showAlert(message, type);
    }
}

function addAPISubscription(selectElement) {
    const selectedOption = selectElement.options[selectElement.selectedIndex];
    const subscriptionPolicies = JSON.parse(selectedOption.getAttribute("data-policies") || "[]");
    const planSelect = document.getElementById("planSelect");

    planSelect.innerHTML = '<option value="" disabled selected>Select a Plan</option>';

    subscriptionPolicies.forEach(policy => {
        const option = document.createElement("option");
        option.value = policy.policyID;
        option.textContent = policy.displayName;
        option.setAttribute("data-policyName", policy.policyName);
        planSelect.appendChild(option);
    });

}

async function removeSubscription() {
    const modal = document.getElementById('deleteConfirmation');
    const orgID = modal.dataset.param1;
    const appID = modal.dataset.param2;
    const apiRefID = modal.dataset.param3;
    const subID = modal.dataset.param4;

    try {
        const response = await fetch(`/devportal/organizations/${orgID}/subscriptions?appID=${appID}&apiReferenceID=${apiRefID}&subscriptionID=${subID}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
        });
        if (response.ok) {
            await showAlert(`Unsubscribed successfully!`, 'success');
            const url = new URL(window.location.origin + window.location.pathname);
            window.location.href = url.toString();
        } else {
            const responseData = await response.json();
            console.error('Failed to unsubscribe:', responseData);
            await showAlert(`Failed to unsubscribe.\n${responseData.description}`, 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        await showAlert(`An error occurred.\n${error.message}`, 'error');
    }
}