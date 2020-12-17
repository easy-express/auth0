import { EasyExpressServer, IEasyExpressAttachableModule } from '@easy-express/server';

import jwt, { RequestHandler } from 'express-jwt';
import jwtAuthz from 'express-jwt-authz';
import jwksRsa from 'jwks-rsa';

class Auth0Module implements IEasyExpressAttachableModule {
  // Authorization middleware. When used, the
  // Access Token must exist and be verified against
  // the Auth0 JSON Web Key Set
  private checkJwt: jwt.RequestHandler;
  private server: EasyExpressServer | undefined;

  constructor() {
    this.checkJwt = jwt({
      // Dynamically provide a signing key
      // based on the kid in the header and
      // the signing keys provided by the JWKS endpoint.
      secret: jwksRsa.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`,
      }),
      // Validate the audience and the issuer.
      audience: process.env.AUTH0_AUDIENCE,
      issuer: `https://${process.env.AUTH0_DOMAIN}/`,
      algorithms: ['RS256'],
    });
  }

  public attachTo(server: EasyExpressServer): Promise<unknown> {
    this.server = server;
    return new Promise(() => {});
  }

  public definePrivateGet(route: string, handler: RequestHandler[]) {
    this.server?.instance.get(route, this.checkJwt, handler);
  }
  public definePublicGet(route: string, handler: RequestHandler[]) {
    this.server?.instance.get(route, handler);
  }
  public defineScopedGet(route: string, scopes: string[], handler: RequestHandler[]) {
    this.server?.instance.get(route, this.checkJwt, jwtAuthz(scopes), handler);
  }

  public definePrivatePost(route: string, handler: RequestHandler[]) {
    this.server?.instance.post(route, this.checkJwt, handler);
  }
  public definePublicPost(route: string, handler: RequestHandler[]) {
    this.server?.instance.post(route, handler);
  }
  public defineScopedPost(route: string, scopes: string[], handler: RequestHandler[]) {
    this.server?.instance.post(route, this.checkJwt, jwtAuthz(scopes), handler);
  }
}
