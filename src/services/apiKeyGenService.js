/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
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
 * "AS IS" BASIS, WITHOUT WARRANTIES OR ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/* eslint-disable no-undef */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const logger = require('../config/logger');
const CLIAPIKey = require('../models/cliApiKey');
const constants = require('../utils/constants');
const util = require('../utils/util');
const secret = require(process.cwd() + '/secret.json');

const API_KEY_PREFIX = 'dpak';
const API_KEY_VERSION = 'v1';
const KEY_NAME_PATTERN = /^[a-z0-9][a-z0-9_-]{0,127}$/;

function accessTokenPresent(req) {
    if (req.user) {
        return req.user[constants.ACCESS_TOKEN];
    }
    if (req.headers.authorization) {
        return req.headers.authorization.split(' ')[1];
    }
    return null;
}

function hashAPIKey(apiKey) {
    return crypto
        .createHmac('sha256', secret.apiKeySecret)
        .update(apiKey)
        .digest('base64url');
}

function normalizeScopes(rawScopes, fallbackScopes) {
    if (Array.isArray(rawScopes)) {
        return rawScopes
            .map(scope => typeof scope === 'string' ? scope.trim() : '')
            .filter(Boolean);
    }
    if (typeof rawScopes === 'string') {
        return rawScopes.split(/\s+/).map(scope => scope.trim()).filter(Boolean);
    }
    return fallbackScopes;
}

function parseExpiry(rawExpiry) {
    if (rawExpiry === undefined || rawExpiry === null || rawExpiry === '') {
        return null;
    }

    let expiryMs;
    const rawValue = typeof rawExpiry === 'string' ? rawExpiry.trim() : rawExpiry;
    const numericExpiry = Number(rawValue);
    if (Number.isFinite(numericExpiry)) {
        expiryMs = Math.abs(numericExpiry) < 1e12
            ? Math.floor(numericExpiry * 1000)
            : Math.floor(numericExpiry);
    } else if (typeof rawValue === 'string') {
        expiryMs = Date.parse(rawValue);
    }

    if (!Number.isFinite(expiryMs)) {
        return null;
    }

    const expiresAt = new Date(expiryMs);
    if (expiresAt <= new Date()) {
        return null;
    }
    return expiresAt;
}

const generateCLIAPIKey = async (req, res) => {
    if (!secret.apiKeySecret) {
        return res.status(500).json({
            code: '500',
            message: 'Internal Server Error',
            description: 'apiKeySecret is not configured'
        });
    }

    const accessToken = accessTokenPresent(req);
    const decodedAccessToken = accessToken ? jwt.decode(accessToken) : null;
    if (!decodedAccessToken) {
        return res.status(401).json({
            code: '401',
            message: 'Unauthorized',
            description: 'A bearer access token is required to generate a CLI API key'
        });
    }

    const userId = decodedAccessToken.sub;
    const orgId = req.params.orgId;
    const { name } = req.body || {};
    const expiryInput = req.body?.expiredAt ?? req.body?.expired_at ?? req.body?.expiresAt;
    const expiredAt = parseExpiry(expiryInput);
    const tokenScopes = normalizeScopes(decodedAccessToken?.scope, []);
    const requestedScopes = normalizeScopes(req.body?.scopes, [constants.SCOPES.DEVELOPER]);

    if (!userId) {
        return res.status(400).json({
            code: '400',
            message: 'Bad Request',
            description: 'sub claim is required to generate a user-bound CLI API key'
        });
    }
    if (!orgId) {
        return res.status(400).json({
            code: '400',
            message: 'Bad Request',
            description: 'orgId is required'
        });
    }
    if (typeof name !== 'string' || !KEY_NAME_PATTERN.test(name.trim())) {
        return res.status(400).json({
            code: '400',
            message: 'Bad Request',
            description: 'name must match ^[a-z0-9][a-z0-9_-]{0,127}$'
        });
    }
    if (!expiredAt) {
        return res.status(400).json({
            code: '400',
            message: 'Bad Request',
            description: 'expiredAt must be a future timestamp'
        });
    }
    if (requestedScopes.length === 0) {
        return res.status(400).json({
            code: '400',
            message: 'Bad Request',
            description: 'At least one scope is required'
        });
    }
    if (requestedScopes.includes(constants.SCOPES.ADMIN) && !tokenScopes.includes(constants.SCOPES.ADMIN)) {
        return res.status(403).json({
            code: '403',
            message: 'Forbidden',
            description: 'Admin scoped CLI API keys require an access token with admin scope'
        });
    }

    try {
        const keyId = crypto.randomUUID();
        const secretPart = crypto.randomBytes(32).toString('base64url');
        const apiKey = `${API_KEY_PREFIX}_${API_KEY_VERSION}_${keyId}_${secretPart}`;
        const keyHash = hashAPIKey(apiKey);
        const normalizedScopes = requestedScopes.join(' ');

        await CLIAPIKey.create({
            API_KEY_ID: keyId,
            ORG_ID: orgId,
            USER_ID: userId,
            NAME: name.trim(),
            KEY_HASH: keyHash,
            SCOPES: normalizedScopes,
            STATUS: 'ACTIVE',
            EXPIRED_AT: expiredAt
        });

        logger.info('Generated CLI API key', {
            orgId,
            userId,
            keyId,
            scopes: normalizedScopes
        });

        return res.status(201).json({
            apiKey,
            apiKeyId: keyId,
            name: name.trim(),
            scopes: normalizedScopes,
            expiredAt: expiredAt.toISOString()
        });
    } catch (error) {
        logger.error('Error occurred while generating CLI API key', {
            orgId,
            userId,
            error: error.message,
            stack: error.stack
        });
        util.handleError(res, error);
    }
};

module.exports = {
    API_KEY_PREFIX,
    API_KEY_VERSION,
    generateCLIAPIKey,
    hashAPIKey
};
