/**
 *    SPDX-License-Identifier: Apache-2.0
 */
import { helper } from '../common/helper';
import { responder } from './requestutils';
const AuthorizationService = require('../auth/authorization-service');

const logger = helper.getLogger('Auth');

/**
 *
 *
 * @param {*} router
 * @param {*} platform
 */
export async function authroutes(router: any, platform: any) {
	const proxy = platform.getProxy();

	/**
	 * *
	 * Network list
	 * GET /networklist -> /login
	 * curl -i 'http://<host>:<port>/networklist'
	 */

	router.get(
		'/networklist',
		responder(async (req: any) => {
			const networkList = await proxy.networkList(req);
			return { networkList };
		})
	);

	/**
	 * *
	 * Login
	 * POST /login -> /login
	 * curl -X POST -H 'Content-Type: application/json' -d '{ 'user': '<user>', 'password': '<password>' }' -i 'http://<host>:<port>/login'
	 */
	router.post('/login', async (req, res, next) => {
		logger.debug('req.body', req.body);
		try {
			const loginResponse = await AuthorizationService.login(
				req.body.user,
				req.body.password
			);

			const cookieName =
				process.env.AUTH_SERVICE_COOKIE_NAME || 'org.apache.fincn.refreshToken';
			res.cookie(cookieName, loginResponse.refreshToken, { sameSite: 'none', secure: true });

			return res.status(200).json({
				success: true,
				message: 'You have successfully logged in!',
				token: loginResponse.accessToken
			});
		} catch (error) {
			return res.status(400).json({
				success: false,
				message: error.toString()
			});
		}
	});

	router.post('/logout', async (req, res, next) => {
		logger.debug('req.body', req.body);
		req.logout();
		const cookieName =
			process.env.AUTH_SERVICE_COOKIE_NAME || 'org.apache.fincn.refreshToken';
		res.clearCookie(cookieName).send();
		res.send();
	});
}
