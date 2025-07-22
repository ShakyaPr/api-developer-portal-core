/* eslint-disable no-undef */
/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
const { invokeApiRequest, invokeGraphQLRequest } = require('../utils/util');
const config = require(process.cwd() + '/config');
const controlPlaneUrl = config.controlPlane.url;
const controlPlaneGraphqlUrl = config.controlPlane.graphqlURL;
const util = require('../utils/util');
const passport = require('passport');
const { Strategy: CustomStrategy } = require('passport-custom');
const adminDao = require('../dao/admin');
const constants = require('../utils/constants');
const { ApplicationDTO } = require('../dto/application');
const { Sequelize } = require("sequelize");
const adminService = require('../services/adminService');
const apiDao = require('../dao/apiMetadata');
const sdkJobService = require('../services/sdkJobService');
const path = require('path');
const fs = require('fs');

// ***** POST / DELETE / PUT Functions ***** (Only work in production)

// ***** Save Application *****

const saveApplication = async (req, res) => {
    try {
        const orgID = await adminDao.getOrgId(req.user[constants.ORG_IDENTIFIER]);
        const application = await adminDao.createApplication(orgID, req.user.sub, req.body);
        return res.status(201).json(new ApplicationDTO(application.dataValues));
    } catch (error) {
        console.error("Error occurred while creating the application", error);
        util.handleError(res, error);
    }
};

// ***** Update Application *****

const updateApplication = async (req, res) => {
    try {
        const orgID = await adminDao.getOrgId(req.user[constants.ORG_IDENTIFIER]);
        const appID = req.params.applicationId;
        const [updatedRows, updatedApp] = await adminDao.updateApplication(orgID, appID, req.user.sub, req.body);
        if (!updatedRows) {
            throw new Sequelize.EmptyResultError("No record found to update");
        }
        res.status(200).send(new ApplicationDTO(updatedApp[0].dataValues));
    } catch (error) {
        console.error("Error occurred while updating the application", error);
        util.handleError(res, error);
    }
};

// ***** Delete Application *****

const deleteApplication = async (req, res) => {
    try {
        const orgID = await adminDao.getOrgId(req.user[constants.ORG_IDENTIFIER]);
        const applicationId = req.params.applicationId;
        try {
            //delete the CP application
            //TODO: handle non-shared scenarios
            const app = await adminDao.getApplicationKeyMapping(orgID, applicationId, true);
            if (app.length > 0) {
                cpAppID = app[0].dataValues.CP_APP_REF;
                await invokeApiRequest(req, 'DELETE', `${controlPlaneUrl}/applications/${cpAppID}`, {}, {});
            }
            const appDeleteResponse = await adminDao.deleteApplication(orgID, applicationId, req.user.sub);
            if (appDeleteResponse === 0) {
                throw new Sequelize.EmptyResultError("Resource not found to delete");
            } else {
                res.status(200).send("Resouce Deleted Successfully");
            }
        } catch (error) {
            if (error.statusCode === 404) {
                const appDeleteResponse = await adminDao.deleteApplication(orgID, applicationId, req.user.sub);
                if (appDeleteResponse === 0) {
                    throw new Sequelize.EmptyResultError("Resource not found to delete");
                } else {
                    res.status(200).send("Resouce Deleted Successfully");
                }
            }
            console.error("Error occurred while deleting the application", error);
            util.handleError(res, error);
        }
    } catch (error) {
        console.error("Error occurred while deleting the application", error);
        util.handleError(res, error);
    }
}

// ***** Save Application *****

const resetThrottlingPolicy = async (req, res) => {
    try {
        const applicationId = req.params.applicationId;
        const { userName } = req.body;
        const responseData = await invokeApiRequest(req, 'POST', `${controlPlaneUrl}/applications/${applicationId}/reset-throttle-policy`, {
            'Content-Type': 'application/json'
        }, {
            userName
        });
        res.status(200).json({ message: responseData.message });
    } catch (error) {
        console.error("Error occurred while resetting the application", error);
        util.handleError(res, error);
    }
};

// ***** Generate API Keys *****

const generateAPIKeys = async (req, res) => {
    try {
        const requestBody = req.body;
        const apiID = requestBody.apiId;
        const orgID = await adminDao.getOrgId(req.user[constants.ORG_IDENTIFIER]);
        let cpAppID = requestBody.applicationId;

        const nonSharedKeyMapping = await adminDao.getApplicationAPIMapping(orgID, requestBody.devportalAppId, apiID, cpAppID, false);
        const sharedKeyMapping = await adminDao.getApplicationAPIMapping(orgID, requestBody.devportalAppId, apiID, cpAppID, true);

        if (!(nonSharedKeyMapping.length > 0 || sharedKeyMapping.length > 0)) { 
            const cpApp = await adminService.createCPApplication(req, requestBody.devportalAppId);
            cpAppID = cpApp.applicationId;

            const apiSubscription = await adminService.createCPSubscription(req, apiID, cpAppID, requestBody.subscriptionPlan);

            const appKeyMappping = {
                orgID: orgID,
                appID: requestBody.devportalAppId,
                cpAppRef: cpAppID,
                apiRefID: apiSubscription.apiId,
                subscriptionRefID: apiSubscription.subscriptionId,
                sharedToken: false,
                tokenType: constants.TOKEN_TYPES.API_KEY
            }
            await adminDao.createApplicationKeyMapping(appKeyMappping);
        } else if (!(nonSharedKeyMapping[0]?.dataValues.SUBSCRIPTION_REF_ID || sharedKeyMapping[0]?.dataValues.SUBSCRIPTION_REF_ID)) {
            const apiSubscription = await adminService.createCPSubscription(req, apiID, cpAppID, requestBody.subscriptionPlan);
            const appKeyMappping = {
                orgID: orgID,
                appID: requestBody.devportalAppId,
                cpAppRef: cpAppID,
                apiRefID: apiSubscription.apiId,
                subscriptionRefID: apiSubscription.subscriptionId,
                sharedToken: false,
                tokenType: constants.TOKEN_TYPES.API_KEY
            }
            await adminDao.updateApplicationKeyMapping(apiSubscription.apiId, appKeyMappping);
        }
        
        const query = `
        query ($orgUuid: String!, $projectId: String!) {
          environments(orgUuid: $orgUuid, projectId: $projectId) {
            name
            templateId
          }
        }
      `;

        const variables = {
            orgUuid: req.user[constants.ORG_IDENTIFIER],
            projectId: requestBody.projectID
        };

        const orgDetails = await invokeGraphQLRequest(req, `${controlPlaneGraphqlUrl}`, query, variables, {});
        const environments = orgDetails?.data?.environments || [];
        const apiHandle = await apiDao.getAPIHandle(orgID, req.body.apiId);

        requestBody.name = apiHandle + "-" + cpAppID;
        requestBody.environmentTemplateId = environments.find(env => env.name === 'Production').templateId;
        requestBody.applicationId = cpAppID;
        delete requestBody.projectID;
        delete requestBody.devportalAppId;

        const responseData = await invokeApiRequest(req, 'POST', `${controlPlaneUrl}/api-keys/generate`, {
            'Content-Type': 'application/json'
        }, requestBody);
        responseData.appRefId = cpAppID;
        res.status(200).json(responseData);
    } catch (error) {
        console.error("Error occurred while deleting the application", error);
        util.handleError(res, error);
    }
};

const revokeAPIKeys = async (req, res) => {
    const apiKeyID = req.params.apiKeyID;
    try {
        const responseData = await invokeApiRequest(req, 'POST', `${controlPlaneUrl}/api-keys/${apiKeyID}/revoke`, {}, {});
        // await adminDao.deleteAppKeyMapping(await adminDao.getOrgId((req.user[constants.ORG_IDENTIFIER])), req.body.applicationId, req.body.apiRefID);
        res.status(200).json(responseData);
    } catch (error) {
        console.error("Error occurred while revoking the API key", error);
        util.handleError(res, error);
    }
}

const regenerateAPIKeys = async (req, res) => {
    const apiKeyID = req.params.apiKeyID;
    try {
        const responseData = await invokeApiRequest(req, 'POST', `${controlPlaneUrl}/api-keys/${apiKeyID}/regenerate`, {}, {});
        res.status(200).json(responseData);
    } catch (error) {
        console.error("Error occurred while revoking the API key", error);
        util.handleError(res, error);
    }
}

const generateApplicationKeys = async (req, res) => {
    try {
        const applicationId = req.params.applicationId;
        const responseData = await invokeApiRequest(req, 'POST', `${controlPlaneUrl}/applications/${applicationId}/generate-keys`, {}, req.body);
        res.status(200).json(responseData);
    } catch (error) {
        console.error("Error occurred while generating the application keys", error);
        util.handleError(res, error);
    }
};

const generateOAuthKeys = async (req, res) => {
    try {
        const applicationId = req.params.applicationId;
        const keyMappingId = req.params.keyMappingId;
        const responseData = await invokeApiRequest(req, 'POST', `${controlPlaneUrl}/applications/${applicationId}/oauth-keys/${keyMappingId}/generate-token`, {}, req.body);
        res.status(200).json(responseData);
    } catch (error) {
        console.error("Error occurred while generating the OAuth keys", error);
        util.handleError(res, error);
    }
};

const revokeOAuthKeys = async (req, res) => {
    try {
        const applicationId = req.params.applicationId;
        const keyMappingId = req.params.keyMappingId;
        const responseData = await invokeApiRequest(req, 'DELETE', `${controlPlaneUrl}/applications/${applicationId}/oauth-keys/${keyMappingId}`, {}, {});
        res.status(200).json(responseData);
    } catch (error) {
        console.error("Error occurred while generating the OAuth keys", error);
        util.handleError(res, error);
    }
};

const cleanUp = async (req, res) => {
    try {
        const applicationId = req.params.applicationId;
        const keyMappingId = req.params.keyMappingId;
        const responseData = await invokeApiRequest(req, 'POST', `${controlPlaneUrl}/applications/${applicationId}/oauth-keys/${keyMappingId}/clean-up`, {}, req.body);
        res.status(200).json(responseData);
    } catch (error) {
        console.error("Error occurred while generating the OAuth keys", error);
        util.handleError(res, error);
    }
};

const updateOAuthKeys = async (req, res) => {

    let tokenDetails = req.body;
    try {
        const applicationId = req.params.applicationId;
        const keyMappingId = req.params.keyMappingId;
        const responseData = await invokeApiRequest(req, 'PUT', `${controlPlaneUrl}/applications/${applicationId}/oauth-keys/${keyMappingId}`, {}, tokenDetails);
        res.status(200).json(responseData);
    } catch (error) {
        console.error("Error occurred while generating the OAuth keys", error);
        util.handleError(res, error);
    }
};

const login = async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    const defaultUser = config.defaultAuth.users.find(user => user.username === username && user.password === password);
    passport.use(
        'default-auth',
        new CustomStrategy((req, done) => {
            if (defaultUser) {
                const user = { ...defaultUser };
                return done(null, user);
            } else {
                return done(null, false, { message: 'Invalid credentials' });
            }
        })
    );

    passport.authenticate('default-auth', (err, user, info) => {
        if (err) {
            console.error("Error occurred while logging in", err);
            return util.handleError(res, err);
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        req.logIn(user, (err) => {
            if (err) {
                return util.handleError(res, err);
            }
            res.status(200).json({ message: 'Login successful' });
        });
    })(req, res);
};

// ***** Generate SDK *****

const generateSDK = async (req, res) => {
    try {
        const { selectedAPIs, sdkConfiguration } = req.body;
        const applicationId = req.params.applicationId;
        const { orgName } = sdkConfiguration;

        // Validate input - require at least 1 API
        if (!selectedAPIs || selectedAPIs.length < 1) {
            return res.status(400).json({
                success: false,
                message: 'At least 1 API must be selected for SDK generation'
            });
        }

        if (!sdkConfiguration) {
            return res.status(400).json({
                success: false,
                message: 'Please provide SDK configuration details'
            });
        }

        // Validate AI description is provided
        if (!sdkConfiguration.description || sdkConfiguration.description.trim() === '') {
            return res.status(400).json({
                success: false,
                message: 'AI description is required for SDK generation'
            });
        }

        const organization = await adminDao.getOrganization(orgName);
        const orgId = organization.ORG_ID;

        // Create job for tracking progress
        const jobPayload = {
            selectedAPIs,
            sdkConfiguration,
            applicationId,
            orgId
        };
        const job = await sdkJobService.createJob(applicationId, jobPayload);
        const jobId = job.JOB_ID;

        // Send immediate response with job ID
        res.json({
            success: true,
            message: 'SDK generation job started successfully',
            data: {
                jobId: jobId,
                status: 'PENDING',
                progress: 0,
                currentStep: 'Initializing',
                sseEndpoint: `/devportal/applications/${applicationId}/sdk/job-progress/${jobId}`
            }
        });
        
    } catch (error) {
        console.error('Error starting SDK generation job:', error);
        res.status(500).json({
            success: false,
            message: 'Error starting SDK generation job',
            error: error.message
        });
    }
};

const streamSDKProgress = (req, res) => {
    const { jobId } = req.params;

    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Cache-Control'
    });

    console.log(`Client connected to SSE for job: ${jobId}`);

    const onProgress = (progressData) => {
        if (progressData.jobId === jobId) {
            const dataToSend = { ...progressData, type: 'progress' };
            res.write(`data: ${JSON.stringify(dataToSend)}\n\n`);
        }
    };

    sdkJobService.on('progress', onProgress);

    // Send initial ping
    res.write(`data: ${JSON.stringify({ type: 'ping', jobId })}\n\n`);

    req.on('close', () => {
        console.log(`Client disconnected from SSE for job: ${jobId}`);
        sdkJobService.removeListener('progress', onProgress);
    });
};

// ***** Cancel SDK Job *****

const cancelSDK = async (req, res) => {
    try {
        const { jobId } = req.params;
        
        console.log(`Received request to cancel SDK job: ${jobId}`);
        
        await sdkJobService.cancelJob(jobId);
        
        res.status(200).json({ 
            success: true, 
            message: 'SDK generation cancelled successfully',
            jobId: jobId
        });
        
    } catch (error) {
        console.error('Error cancelling SDK generation:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message || 'Failed to cancel SDK generation'
        });
    }
};

/**
 * Utility function to clean up generated SDK files and folders older than 10 minutes
 * This runs periodically to remove all files and folders in the generated-sdks directory
 */
const cleanupGeneratedSDKs = async () => {
    try {
        const generatedSdksDir = path.join(process.cwd(), 'generated-sdks');
        
        if (!(await fs.promises.access(generatedSdksDir).then(() => true).catch(() => false))) {
            return;
        }
        
        const tenMinutesAgo = Date.now() - (10 * 60 * 1000); // 10 minutes in milliseconds
        
        try {
            const items = await fs.promises.readdir(generatedSdksDir, { withFileTypes: true });
            let cleanedCount = 0;
            
            for (const item of items) {
                const itemPath = path.join(generatedSdksDir, item.name);
                
                try {
                    const stats = await fs.promises.stat(itemPath);
                    
                    // Check if the item is older than 10 minutes (using creation time)
                    if (stats.birthtime.getTime() < tenMinutesAgo) {
                        if (item.isDirectory()) {
                            await fs.promises.rm(itemPath, { recursive: true, force: true });
                            console.log(`Cleaned up SDK directory (${Math.round((Date.now() - stats.birthtime.getTime()) / 60000)} minutes old): ${itemPath}`);
                        } else {
                            await fs.promises.unlink(itemPath);
                            console.log(`Cleaned up SDK file (${Math.round((Date.now() - stats.birthtime.getTime()) / 60000)} minutes old): ${itemPath}`);
                        }
                        cleanedCount++;
                    }
                } catch (error) {
                    console.warn(`Error processing SDK item ${itemPath}:`, error.message);
                }
            }
            
            if (cleanedCount > 0) {
                console.log(`SDK cleanup completed: ${cleanedCount} items removed from generated-sdks directory`);
            }
            
        } catch (error) {
            console.warn(`Error reading generated-sdks directory: ${error.message}`);
        }
        
    } catch (error) {
        console.error('Error during generated SDK cleanup:', error);
    }
};



// Global variable to store the cleanup interval
let sdkCleanupInterval = null;

/**
 * Start the periodic SDK cleanup process
 * Runs every 5 minutes to check for files/folders older than 10 minutes
 */
const startSDKCleanupScheduler = () => {
    if (sdkCleanupInterval) {
        return; 
    }
    
    console.log('Starting SDK cleanup scheduler - runs every 5 minutes to clean files older than 10 minutes');

    cleanupGeneratedSDKs();
    
    // Set up periodic cleanup every 5 minutes
    sdkCleanupInterval = setInterval(async () => {
        try {
            await cleanupGeneratedSDKs();
        } catch (error) {
            console.error('Error in scheduled SDK cleanup:', error);
        }
    }, 5 * 60 * 1000);
};

/**
 * Stop the periodic SDK cleanup process
 */
const stopSDKCleanupScheduler = () => {
    if (sdkCleanupInterval) {
        clearInterval(sdkCleanupInterval);
        sdkCleanupInterval = null;
        console.log('SDK cleanup scheduler stopped');
    }
};

module.exports = {
    saveApplication,
    updateApplication,
    deleteApplication,
    resetThrottlingPolicy,
    generateAPIKeys,
    generateApplicationKeys,
    generateOAuthKeys,
    revokeOAuthKeys,
    updateOAuthKeys,
    cleanUp,
    login,
    revokeAPIKeys,
    regenerateAPIKeys,
    generateSDK,
    streamSDKProgress,
    cancelSDK,
    startSDKCleanupScheduler,
    stopSDKCleanupScheduler
};