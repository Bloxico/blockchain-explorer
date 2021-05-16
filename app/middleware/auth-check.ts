/*
 * SPDX-License-Identifier: Apache-2.0
 */

const AuthorizationService = require('./auth/athorization-service');

/**
 *  The Auth Checker middleware function.
 */
export const authCheckMiddleware = async (req, res, next) => {
	if (!req.headers.authorization) {
		return res.status(401).end();
	}

	// Get the last part from a authorization header string like "bearer token-value"
	const token = req.headers.authorization.split(' ')[1];

	const userData = await AuthorizationService.check(token);
	console.log('prosao CHECK');
	// console.log(userData)

	req.requestUserId = userData.user;
	req.network = userData.network;

	return next();

	// Decode the token using a secret key-phrase
	// return jwt.verify(token, config.jwt.secret, (err, decoded) => {
	// 	// The 401 code is for unauthorized status
	// 	if (err) {
	// 		return res.status(401).end();
	// 	}

	// 	const requestUserId = decoded.user;

	// 	req.requestUserId = requestUserId;
	// 	req.network = decoded.network;

	// 	// TODO: check if a user exists, otherwise error

	// 	return next();
	// });
};
