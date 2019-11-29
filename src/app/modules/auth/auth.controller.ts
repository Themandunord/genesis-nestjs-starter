import { User } from './../user/models/user.entity';
import { AuthPayload } from './../user/dto/auth.payload';
import { UserService } from './../user/user.service';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from 'nestjs-config';
// import { UserService } from '@modules/user/user.service';
// import { AuthService } from '@modules/auth';
import {
  Controller,
  Get,
  UseGuards,
  Response,
  Request,
  InternalServerErrorException,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import get from 'lodash.get';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly config: ConfigService,
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
  ) {
    this.config = config;
    this.authService = authService;
    this.jwtService = jwtService;
  }

  @Post('refresh_token')
  async refreshToken(@Request() req, @Response() res) {
    const token = get(req, 'cookies.gid', null);
    if (!token) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    let user: User = null;
    let payload: any = {};
    try {
      payload = await this.jwtService.verify(token);
      user = await this.userService.findOne({ id: payload.id });
    } catch (err) {
      throw new InternalServerErrorException(err);
    }
    if (!user) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const accessToken = await this.authService.createToken(user);
    const jwtTokenExpiry = new Date(
      new Date().getTime() +
        get(this.config.get('jwt'), 'accessToken.options.expiresIn', 15 * 60) *
          1000,
    );
    delete user.password;
    const refreshToken = await this.authService.createRefreshToken(user);
    this.authService.sendRefreshToken(
      res,
      refreshToken,
      this.config.get('jwt'),
    );
    res.json({ token: accessToken, jwtTokenExpiry, user });
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  googleLogin() {
    // initiates the Google OAuth2 login flow
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleLoginCallback(@Request() req, @Response() res) {
    // handles the Google OAuth2 callback
    const user: any = req.user;
    const accessToken = await this.authService.createToken(user);
    req.session.accessToken = accessToken;
    res.redirect(this.config.get('api').webUrl());
    // else res.redirect('http://localhost:4200/login/failure');
  }

  @Get('hasura')
  // @UseGuards(AuthGuard())
  async hasura(@Request() req, @Response() res) {
    try {
      const token =
        get(req, 'session.accessToken', null) || req.get('Authorization');
      const payload = await this.jwtService.verify(token);
      const user = await this.userService.findOne({ id: payload.id });
      if (user) {
        const hasuraVariables = {
          'X-Hasura-User-Id': user.id, // result.user_id
        };
        res.json(hasuraVariables);
      } else {
        res.sendStatus(401);
      }
    } catch (error) {
      res.sendStatus(401);
    }
  }
}
