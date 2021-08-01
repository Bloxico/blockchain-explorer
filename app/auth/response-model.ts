export class AuthServiceResponseModel {
	access_token: string;
	token_type: string;
	refresh_token: string;
	expires_in: number;
	score: string;
	id: string;
	roles: string[];
	jti: string;
}
