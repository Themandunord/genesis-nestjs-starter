import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthenticationError } from 'apollo-server';
import { ConfigService } from 'nestjs-config';
import { USER_ACTIVE_STATUS } from '../../constants';
import { User } from '../../modules/user/models/user.entity';
import { UserService } from '../user/user.service';
import { CryptoService } from './crypto.service';
// import { sign } from 'jsonwebtoken'dd;

@Injectable()
export class AuthService {
  constructor(
    private readonly cryptoService: CryptoService,
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
    private readonly config: ConfigService,
  ) {
    this.config = config;
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userService.findOne({
      email,
      status: USER_ACTIVE_STATUS,
    });
    if (!user) {
      return null;
    }
    const valid = await this.cryptoService.checkPassword(
      user.password,
      password,
    );
    if (valid) {
      delete user.password;
      return user;
    }
  }

  public async createToken(user: User) {
    const timeInMs = Math.floor(Date.now() / 1000);
    const iat = timeInMs - 30;
    const payload = {
      // tslint:disable-next-line: object-literal-key-quotes
      id: user.id,
      // tslint:disable-next-line:object-literal-key-quotes
      tokenVersion: user.tokenVersion,
      iat,
      'https://hasura.io/jwt/claims': {
        'x-hasura-allowed-roles': [],
        'x-hasura-default-role': user.role,
        'x-hasura-user-id': user.id,
        // 'x-hasura-org-id': '123',
        // 'x-hasura-custom': 'custom-value',
      },
    };
    const accessToken = await this.jwtService.sign(
      payload,
      this.config.get('jwt').accessToken.options,
    );
    return accessToken;
  }

  public async createRefreshToken(user: User) {
    const timeInMs = Math.floor(Date.now() / 1000);
    const iat = timeInMs - 30;
    const payload = {
      id: user.id,
      tokenVersion: user.tokenVersion,
      iat,
    };
    const refreshToken = await this.jwtService.sign(
      payload,
      this.config.get('jwt').refreshToken.options,
    );
    return refreshToken;
  }

  public async getAuthUser(token: string): Promise<User | null> {
    try {
      const payload: any = await this.jwtService.verify(token);
      const user: User = await this.userService.findOne({ id: payload.id });
      return user;
    } catch (e) {
      console.error(e);
    }
    return null;
  }

  public async verify(token: string) {
    try {
      const payload: any = await this.jwtService.verify(token);
      const user: User = await this.userService.findOne({ id: payload.id });
      return user !== null && user.tokenVersion === payload.tokenVersion;
    } catch (e) {
      console.error(e);
      throw new AuthenticationError('GqlAuthGuard');
    }
  }
}
