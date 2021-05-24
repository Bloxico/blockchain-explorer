/*
 * SPDX-License-Identifier: Apache-2.0
 */

import * as jwt from 'jsonwebtoken';
import config from '../explorerconfig.json';
const AuthorizationService = require('../auth/authorization-service');

/**
 *  The Auth Checker middleware function.
 */
export const authCheckMiddleware = async (req, res, next) => {
	if (!req.headers.authorization) {
		return res.status(401).end();
	}

	// Get the last part from a authorization header string like "bearer token-value"
	const token = req.headers.authorization.split(' ')[1];

	// Decode the token using a secret key-phrase
	const jwtSecret = process.env.JWT_SECRET || 'secretKey';
	return jwt.verify(token, jwtSecret, async (err, decoded) => {
		// The 401 code is for unauthorized status
		if (err) {
			console.log('401 response => REFRESH TOKEN');

			const loginResponse = await AuthorizationService.refresh();

			// return res.status(401).end();
		}

		req.network = 'slaff-test-network';

		console.log('OKOKOK');

		// TODO: check if a user exists, otherwise error

		return next();
	});
};
