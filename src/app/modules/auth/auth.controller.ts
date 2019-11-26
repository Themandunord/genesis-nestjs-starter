import { UserService } from './../user/user.service';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from 'nestjs-config';
// import { UserService } from '@modules/user/user.service';
// import { AuthService } from '@modules/auth';
import { Controller, Get, UseGuards, Res, Req } from '@nestjs/common';
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

  @Get('google')
  @UseGuards(AuthGuard('google'))
  googleLogin() {
    // initiates the Google OAuth2 login flow
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleLoginCallback(@Req() req, @Res() res) {
    // handles the Google OAuth2 callback
    const user: any = req.user;
    const accessToken = await this.authService.createToken(user);
    req.session.accessToken = accessToken;
    res.redirect(this.config.get('api').webUrl());
    // else res.redirect('http://localhost:4200/login/failure');
  }

  @Get('hasura')
  // @UseGuards(AuthGuard())
  async hasura(@Req() req, @Res() res) {
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
