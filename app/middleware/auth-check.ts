/*
 * SPDX-License-Identifier: Apache-2.0
 */

import * as jwt from 'jsonwebtoken';
import { AuthServiceResponseModel } from '../auth/response-model';
const AuthorizationService = require('../auth/authorization-service');

/**
 *  The Auth Checker middleware function.
 */

export const authCheckMiddleware = function(networkName) {
	return function(req, res, next) {
		const useAuthService = process.env.USE_AUTH_SERVICE == 'true';
		if (!useAuthService) {
			req.network = networkName;
			return next();
		}

		if (!req.headers.authorization) {
			// The 401 code is for unauthorized status
			return res.status(401).end();
		}

		// Get the last part from a authorization header string like "bearer token-value"
		const token = req.headers.authorization.split(' ')[1];

		const cookieName =
			process.env.AUTH_SERVICE_COOKIE_NAME || 'org.apache.fincn.refreshToken';

		// Decode the token using a secret key-phrase
		const jwtSecret = process.env.JWT_SECRET || 'secretKey';
		return jwt.verify(token, jwtSecret, async (err, decoded) => {
			if (err) {
				console.log('decoded ', decoded);

				if (req.cookies && req.cookies[cookieName]) {
					// TODO: If decoded is true, red username from decoded data
					const refreshToken = req.cookies[cookieName];
					const refreshTokenResponse = await AuthorizationService.refresh(
						'explorerUser',
						JSON.parse(refreshToken)
					);

					res.cookie(cookieName, refreshTokenResponse.refreshToken, {
						sameSite: 'none',
						secure: true
					});
				}
			}
			req.network = networkName;
			return next();
		});
	};
};
