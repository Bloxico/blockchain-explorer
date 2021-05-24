export class AuthServiceResponseModel {
	statusCode: number;
	message: string;
	data: any;
}

export class AuthServiceLoginResponseModel {
	tokenType: string;
	accessToken: string;
	accessTokenExpiration: string;
	refreshTokenExpiration: string;
	passwordExpiration: string;
}
