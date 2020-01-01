import { UseGuards } from '@nestjs/common';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { JwtService } from '@nestjs/jwt';
import { AuthenticationError } from 'apollo-server';
import get from 'lodash.get';
import { ConfigService } from 'nestjs-config';
import { RedisService } from 'nestjs-redis';
import { MailService } from '../../../core/mailer';
import { AppService } from '../../app.service';
import {
  REDIS_CONFIRM_TOKEN_PREFIX,
  REDIS_FORGOT_PASSWORD_TOKEN_PREFIX,
  REDIS_LOGIN_OTP_PREFIX,
  USER_ACTIVE_STATUS,
} from '../../constants';
import { AuthService } from '../auth/auth.service';
import { USER_ACTIVE_VERIFICATION } from './../../constants';
import { GqlAuthGuard } from './../auth/guards/graphql-auth.guard';
import { AuthPayload } from './dto/auth.payload';
import { ChangePasswordArgs } from './dto/change.password.args';
import { LoginArgs } from './dto/login.args';
import { ResetPasswordArgs } from './dto/reset.password.args';
import { UserCreateInput } from './dto/user.create.input';
import { User } from './models/user.entity';
import { UserService } from './user.service';

@Resolver(of => User)
export class UserResolver {
  constructor(
    private readonly appService: AppService,
    private readonly userService: UserService,
    private readonly authService: AuthService,
    private readonly mailService: MailService,
    private readonly redisService: RedisService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  @Mutation(returns => AuthPayload)
  async login(
    @Args() loginArgs: LoginArgs,
    @Context() ctx,
  ): Promise<AuthPayload> {
    const { email, password } = loginArgs;
    const user: User = await this.authService.validateUser(email, password);
    if (!user) {
      this.appService.throwAuthenticationError(`Invalid login credentials`);
    }

    try {
      await this.userService.update(
        {
          lastLoginAt: new Date(),
        },
        {
          id: user.id,
        },
      );
      const token = await this.authService.createToken(user);
      const tokenExpiry = new Date(
        new Date().getTime() +
          get(
            this.configService.get('jwt'),
            'accessToken.options.expiresIn',
            15 * 60,
          ) *
            1000,
      );
      delete user.password;
      const refreshToken = await this.authService.createRefreshToken(user);
      this.authService.sendRefreshToken(
        ctx.res,
        refreshToken,
        this.configService.get('jwt'),
      );
      return { token, tokenExpiry, user };
    } catch (e) {
      this.appService.handleInternalError(e);
    }
  }

  @Mutation(returns => Boolean)
  async sendLoginOTP(@Args('email') email: string): Promise<boolean> {
    // send mail with defined transport object
    try {
      const user: User = await this.userService.findOne({ email });
      if (!user) {
        return false;
      }
      const info = this.mailService.sendOTPEmail(
        email,
        user.id,
        'Login OTP for Genesis',
      );
      return info !== null;
    } catch (error) {
      this.appService.handleInternalError(error);
    }
    return false;
  }

  @Mutation(returns => AuthPayload)
  async loginWithOTP(
    @Args() loginArgs: LoginArgs,
    @Context() ctx,
  ): Promise<AuthPayload> {
    const { email, otp } = loginArgs;
    const key = REDIS_LOGIN_OTP_PREFIX + email + otp;
    const redis = this.redisService.getClient();
    const id = await redis.get(key);

    if (!id) {
      return null;
    }
    await redis.del(key);
    const user: User = await this.userService.findOne({ id });
    if (!user) {
      this.appService.throwAuthenticationError(`Invalid login credentials`);
    }

    try {
      await this.userService.update(
        {
          lastLoginAt: new Date(),
        },
        {
          id: user.id,
        },
      );
      const token = await this.authService.createToken(user);
      const tokenExpiry = new Date(
        new Date().getTime() +
          get(
            this.configService.get('jwt'),
            'accessToken.options.expiresIn',
            15 * 60,
          ) *
            1000,
      );
      delete user.password;
      const refreshToken = await this.authService.createRefreshToken(user);
      this.authService.sendRefreshToken(
        ctx.res,
        refreshToken,
        this.configService.get('jwt'),
      );
      return { token, tokenExpiry, user };
    } catch (error) {
      this.appService.handleInternalError(error);
    }
  }

  @Query(returns => User)
  @UseGuards(GqlAuthGuard)
  async me(@Context() ctx): Promise<User | null> {
    try {
      const user = get(ctx, 'req.user', null);
      if (user) {
        return user;
      } else {
        this.appService.throwAuthenticationError();
      }
    } catch (e) {
      this.appService.throwAuthenticationError();
    }
  }

  @Mutation(returns => Boolean)
  @UseGuards(GqlAuthGuard)
  async logoutfromAllDevices(@Context() ctx) {
    try {
      const user: User = get(ctx, 'req.user', null);
      if (user) {
        await User.update(
          { tokenVersion: user.tokenVersion + 1 },
          { id: user.id },
        );
        return true;
      } else {
        this.appService.throwAuthenticationError();
      }
    } catch (e) {
      this.appService.handleInternalError(e);
    }
    return false;
  }

  @Mutation(returns => Boolean)
  @UseGuards(GqlAuthGuard)
  async logout(@Context() ctx) {
    try {
      ctx.res.cookie('gid', '', {
        httpOnly: true,
        expires: new Date(0),
      });
      return true;
    } catch (error) {
      this.appService.handleInternalError(error);
    }
  }

  @Mutation(returns => Boolean)
  async forgotPassword(@Args('email') email: string): Promise<boolean> {
    // send mail with defined transport object
    try {
      const user: User = await this.userService.findOne({ email });
      if (!user) {
        return false;
      }
      const result = await this.mailService.sendForgotPasswordEmail(
        email,
        user.id,
      );
      return result !== null;
    } catch (error) {
      this.appService.handleInternalError(error);
    }
    return true;
  }

  @Mutation(returns => Boolean)
  @UseGuards(GqlAuthGuard)
  async changePassword(
    @Args() changePasswordArgs: ChangePasswordArgs,
    @Context() ctx,
  ) {
    const user = get(ctx, 'req.user', null);
    if (user) {
      const { password, currentPassword } = changePasswordArgs;
      let validUser: User = null;
      try {
        validUser = await this.authService.validateUser(
          user.email,
          currentPassword,
        );
      } catch (error) {
        this.appService.thorwInternalError(error);
      }
      if (validUser) {
        const newPassword = await this.userService.encrypt(password);
        await this.userService.update(
          {
            password: newPassword,
          },
          {
            id: validUser.id,
          },
        );
        return true;
      } else {
        this.appService.throwUserInputError('Invalid change password data');
      }
    } else {
      this.appService.throwAuthenticationError();
    }
  }

  @Mutation(returns => Boolean)
  async resetPassword(@Args() resetPasswordArgs: ResetPasswordArgs) {
    try {
      const { password, token } = resetPasswordArgs;
      const key = REDIS_FORGOT_PASSWORD_TOKEN_PREFIX + token;
      const redis = this.redisService.getClient();
      const id = await redis.get(key);

      if (!id) {
        return null;
      }

      const newPassword = await this.userService.encrypt(password);
      await this.userService.update(
        {
          password: newPassword,
        },
        {
          id,
        },
      );
      await redis.del(key);
      return true;
    } catch (error) {
      this.appService.handleInternalError(error);
    }
  }

  @Mutation(returns => AuthPayload)
  async refreshToken(@Context() ctx): Promise<AuthPayload> {
    const gid = get(ctx, 'req.cookies.gid', null);
    if (!gid) {
      throw new AuthenticationError('Invalid refresh token');
    }

    let user: User = null;
    let payload: any = {};
    try {
      payload = await this.jwtService.verify(gid);
      user = await this.userService.findOne({ id: payload.id });
    } catch (err) {
      this.appService.thorwInternalError(err);
    }
    if (!user || user.tokenVersion !== payload.tokenVersion) {
      this.appService.throwAuthenticationError('Invalid refresh token');
    }

    const token = await this.authService.createToken(user);
    const tokenExpiry = new Date(
      new Date().getTime() +
        get(
          this.configService.get('jwt'),
          'accessToken.options.expiresIn',
          15 * 60,
        ) *
          1000,
    );
    delete user.password;
    const refreshToken = await this.authService.createRefreshToken(user);
    this.authService.sendRefreshToken(
      ctx.res,
      refreshToken,
      this.configService.get('jwt'),
    );
    return { token, tokenExpiry, user };
  }

  @Mutation(returns => User)
  async signup(@Args('userCreateInput') userCreateInput: UserCreateInput) {
    const errors: any = {};
    const { email, name, username, password } = userCreateInput;
    if (password.length < 6) {
      errors.password = `Password must be at least 6 characters`;
    }

    let user = await this.userService.findOne({ email });

    if (user && user.status === USER_ACTIVE_VERIFICATION) {
      // await this.mailService.sendConfirmationEmail(user.email, user.id);
      return user;
    }

    const emailExists = await this.userService.exists({ email });
    if (emailExists) {
      const message = `Email ${email} is already in use`;
      this.appService.throwValidationError(message);
    }

    if (username) {
      const usernameExists = await this.userService.exists({ username });
      if (usernameExists) {
        const message = `Username ${username} is already in use`;
        this.appService.throwValidationError(message);
      }
    }

    try {
      user = await this.userService.create({
        email,
        name,
        username,
        password,
      });
      await this.mailService.sendConfirmationEmail(user.email, user.id);
    } catch (error) {
      this.appService.thorwInternalError(error);
    }
    return user;
  }

  @Mutation(returns => Boolean)
  async confirm(@Args('token') token: string): Promise<boolean> {
    // send mail with defined transport object
    try {
      const redis = this.redisService.getClient();
      const key = REDIS_CONFIRM_TOKEN_PREFIX + token;
      const id = await redis.get(key);

      if (!id) {
        return false;
      }

      await this.userService.update(
        {
          status: USER_ACTIVE_STATUS,
        },
        {
          id,
        },
      );
      await redis.del(key);
      return true;
    } catch (error) {
      this.appService.thorwInternalError(error);
    }
  }

  @Mutation(returns => Boolean)
  async resendConfirm(@Args('email') email: string): Promise<boolean> {
    // send mail with defined transport object
    try {
      const user: User = await this.userService.findOne({ email });
      if (!user) {
        return false;
      }
      const result = await this.mailService.sendConfirmationEmail(
        email,
        user.id,
      );
      return result !== null;
    } catch (error) {
      this.appService.thorwInternalError(error);
    }
    return true;
  }
}
