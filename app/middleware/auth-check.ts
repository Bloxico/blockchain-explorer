/*
 * SPDX-License-Identifier: Apache-2.0
 */

import * as jwt from 'jsonwebtoken';
const AuthorizationService = require('../auth/authorization-service');

/**
 *  The Auth Checker middleware function.
 */

export const authCheckMiddleware = function(networkName) {
	return async function(req, res, next) {
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

		// Validate the token using a public key
		return jwt.verify(
			token.trim(),
			AuthorizationService.readPublicKey(),
			{ algorithms: ['RS512'] },
			async (err, decoded) => {
				if (!err) {
					req.network = networkName;
					return next();
				}

				// Expired token
				const cookieName =
					process.env.AUTH_SERVICE_COOKIE_NAME || 'org.apache.fincn.refreshToken';

				if (req.cookies && req.cookies[cookieName]) {
					const refreshToken = req.cookies[cookieName];
					const refreshTokenResponse = await AuthorizationService.refresh(
						refreshToken
					);

					res.cookie(cookieName, refreshTokenResponse.refreshToken, {
						sameSite: 'none',
						secure: true
					});

					req.network = networkName;
					return next();
				}
			}
		);
	};
};
