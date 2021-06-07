/*
 * SPDX-License-Identifier: Apache-2.0
 */

import * as jwt from 'jsonwebtoken';
const AuthorizationService = require('../auth/authorization-service');

/**
 *  The Auth Checker middleware function.
 */

export const authCheckMiddleware = function(networkName) {
	return function(req, res, next) {
		if (!req.headers.authorization) {
			// The 401 code is for unauthorized status
			return res.status(401).end();
		}

		// Get the last part from a authorization header string like "bearer token-value"
		const token = req.headers.authorization.split(' ')[1];

		// Decode the token using a secret key-phrase
		const jwtSecret = process.env.JWT_SECRET || 'secretKey';
		return jwt.verify(token, jwtSecret, async (err, decoded) => {
			if (err) {
				const refreshTokenResponse = await AuthorizationService.refresh();

				const cookieName =
					process.env.AUTH_SERVICE_COOKIE_NAME || 'org.apache.fincn.refreshToken';
				res.cookie(cookieName, refreshTokenResponse.refreshToken, { sameSite: 'none', secure: true });
			}
			req.network = networkName;
			return next();
		});
	};
};
