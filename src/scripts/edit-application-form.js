document.addEventListener('DOMContentLoaded', () => {
    const MAX_CHARACTERS = 256;

    // In-place editing functionality
    const setupInlineEditing = () => {
        const applicationName = document.getElementById('applicationName');
        const applicationDescription = document.getElementById('applicationDescription');
        const editNameBtn = document.getElementById('editNameBtn');
        const editDescriptionBtn = document.getElementById('editDescriptionBtn');
        const saveNameBtn = document.getElementById('saveNameBtn');
        const saveDescriptionBtn = document.getElementById('saveDescriptionBtn');
        const cancelNameBtn = document.getElementById('cancelNameBtn');
        const cancelDescriptionBtn = document.getElementById('cancelDescriptionBtn');
        const nameEditActions = document.getElementById('nameEditActions');
        const descriptionEditActions = document.getElementById('descriptionEditActions');
        const nameEditError = document.getElementById('nameEditError');
        const descriptionEditError = document.getElementById('descriptionEditError');
        const inlineEditForm = document.getElementById('inlineEditForm');
        
        if (!applicationName || !applicationDescription) return;
        
        const applicationId = inlineEditForm.dataset.applicationId;
        
        // Make name editable
        editNameBtn.addEventListener('click', () => {
            applicationName.contentEditable = true;
            applicationName.focus();
            editNameBtn.style.display = 'none';
            nameEditActions.style.display = 'inline-flex';
            // Clear any existing error
            nameEditError.style.display = 'none';
        });
        
        // Make description editable
        editDescriptionBtn.addEventListener('click', () => {
            applicationDescription.contentEditable = true;
            applicationDescription.focus();
            editDescriptionBtn.style.display = 'none';
            descriptionEditActions.style.display = 'inline-flex';
            // Clear any existing error
            descriptionEditError.style.display = 'none';
        });
        
        // Cancel name edit
        cancelNameBtn.addEventListener('click', () => {
            applicationName.textContent = applicationName.dataset.original;
            applicationName.contentEditable = false;
            nameEditActions.style.display = 'none';
            editNameBtn.style.display = 'inline-block';
            nameEditError.style.display = 'none';
        });
        
        // Cancel description edit
        cancelDescriptionBtn.addEventListener('click', () => {
            applicationDescription.textContent = applicationDescription.dataset.original;
            applicationDescription.contentEditable = false;
            descriptionEditActions.style.display = 'none';
            editDescriptionBtn.style.display = 'inline-block';
            descriptionEditError.style.display = 'none';
        });
        
        // Save name changes
        saveNameBtn.addEventListener('click', async () => {
            const newName = applicationName.textContent.trim();
            if (!newName) {
                nameEditError.textContent = 'Name cannot be empty';
                nameEditError.style.display = 'block';
                return;
            }
            
            const result = await saveApplicationChanges(applicationId, {
                name: newName,
                description: applicationDescription.dataset.original
            }, nameEditError);
            
            if (result) {
                applicationName.dataset.original = newName;
                applicationName.contentEditable = false;
                nameEditActions.style.display = 'none';
                editNameBtn.style.display = 'inline-block';
                nameEditError.style.display = 'none';
            }
        });
        
        // Save description changes
        saveDescriptionBtn.addEventListener('click', async () => {
            const newDescription = applicationDescription.textContent.trim();
            if (newDescription.length > MAX_CHARACTERS) {
                descriptionEditError.textContent = `Description exceeds ${MAX_CHARACTERS} character limit`;
                descriptionEditError.style.display = 'block';
                return;
            }
            
            const result = await saveApplicationChanges(applicationId, {
                name: applicationName.dataset.original,
                description: newDescription
            }, descriptionEditError);
            
            if (result) {
                document.location.reload();
                // applicationDescription.dataset.original = newDescription;
                // applicationDescription.contentEditable = false;
                // descriptionEditActions.style.display = 'none';
                // editDescriptionBtn.style.display = 'inline-block';
                // descriptionEditError.style.display = 'none';
            }
        });
    };
    
    // Function to save application changes
    const saveApplicationChanges = async (applicationId, data, errorElement) => {
        try {
            if (errorElement) {
                errorElement.style.display = 'none';
            }
            
            const response = await fetch(`/devportal/applications/${applicationId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ...data,
                    type: 'WEB'
                }),
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            
            const responseData = await response.json();
            await showAlert(
                responseData.message || 'Application updated successfully!',
                'success'
            );
            
            return true;
        } catch (error) {
            console.error('Error saving application:', error);
            if (errorElement) {
                errorElement.textContent = 'Failed to update. Please try again.';
                errorElement.style.display = 'block';
            }
            return false;
        }
    };
    
    // Initialize inline editing
    setupInlineEditing();
});
