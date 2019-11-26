import { UnauthorizedException, UseGuards } from '@nestjs/common';
import { Args, Context, Mutation, Query, Resolver } from '@nestjs/graphql';
import { JwtService } from '@nestjs/jwt';
import { AuthenticationError, UserInputError } from 'apollo-server';
import { ApolloError } from 'apollo-server-express';
import { Response } from 'express';
import { GraphQLError } from 'graphql';
import get from 'lodash.get';
import { ConfigService } from 'nestjs-config';
import { RedisService } from 'nestjs-redis';
import { v4 } from 'uuid';
import { MailService } from '../../../core/mailer';
import { AppService } from '../../app.service';
import {
  REDIS_CONFIRM_TOKEN_PREFIX,
  REDIS_FORGOT_PASSWORD_TOKEN_PREFIX,
  REDIS_LOGIN_OTP_PREFIX,
  USER_ACTIVE_STATUS,
} from '../../constants';
import { AuthService } from '../auth/auth.service';
import { GqlAuthGuard } from './../auth/guards/graphql-auth.guard';
import { AuthPayload } from './dto/auth.payload';
import { ChangePasswordArgs } from './dto/change.password.args';
import { LoginArgs } from './dto/login.args';
import { ResetPasswordArgs } from './dto/reset.password.args';
import { UserCreateInput } from './dto/user.create.input';
import { User } from './models/user.entity';
import { UserService } from './user.service';

const handleInternalError = error => {
  if (error instanceof ApolloError) {
    throw error;
  }
  const errId = v4();
  console.log('errId: ', errId);
  console.log(error);
  throw new GraphQLError(`Internal Error: ${errId}`);
};

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

  sendRefreshToken(res: Response, token: string) {
    res.cookie('gid', token, {
      maxAge:
        get(
          this.configService.get('jwt'),
          'accessToken.options.expiresIn',
          60 * 60 * 24 * 7,
        ) * 1000, // convert from minute to milliseconds
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      // path: '/api/refresh_token',
    });
  }

  @Mutation(returns => AuthPayload)
  async login(
    @Args() loginArgs: LoginArgs,
    @Context() ctx,
  ): Promise<AuthPayload> {
    const { email, password } = loginArgs;
    const user: User = await this.authService.validateUser(email, password);
    if (!user) {
      this.appService.throwValidationErrors('login', {
        credentials: `Invalid login credentials`,
      });
    }

    try {
      const token = await this.authService.createToken(user);
      const jwtTokenExpiry = new Date(
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
      this.sendRefreshToken(ctx.res, refreshToken);
      return { token, jwtTokenExpiry, user };
    } catch (e) {
      handleInternalError(e);
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
      handleInternalError(error);
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
      this.appService.throwValidationErrors('login', {
        credentials: `Invalid login credentials`,
      });
    }

    try {
      const token = await this.authService.createToken(user);
      const jwtTokenExpiry = new Date(
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
      this.sendRefreshToken(ctx.res, refreshToken);
      return { token, jwtTokenExpiry, user };
    } catch (error) {
      handleInternalError(error);
    }
  }

  @Query(returns => User)
  @UseGuards(GqlAuthGuard)
  async me(@Context() ctx): Promise<User | null> {
    try {
      return get(ctx, 'req.user', null);
    } catch (e) {
      console.error(e);
      throw new UnauthorizedException();
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
      }
    } catch (e) {
      console.error(e);
      throw new UnauthorizedException();
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
      handleInternalError(error);
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
      handleInternalError(error);
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
        handleInternalError(error);
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
        throw new UserInputError(
          'Invalid credentials provided for change password',
        );
      }
    } else {
      console.log(user);
      throw new UnauthorizedException();
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
      handleInternalError(error);
    }
  }

  @Mutation(returns => AuthPayload)
  async refreshToken(@Context() ctx): Promise<AuthPayload> {
    const token = get(ctx, 'req.cookies.gid', null);
    if (!token) {
      throw new AuthenticationError('Invalid refresh token');
    }

    let user: User = null;
    let payload: any = {};
    try {
      payload = await this.jwtService.verify(token);
      user = await this.userService.findOne({ id: payload.id });
    } catch (err) {
      handleInternalError(err);
    }
    if (!user) {
      throw new AuthenticationError('Invalid refresh token');
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      throw new AuthenticationError('Invalid refresh token');
    }

    const accessToken = await this.authService.createToken(user);
    const jwtTokenExpiry = new Date(
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
    this.sendRefreshToken(ctx.res, refreshToken);
    return { token: accessToken, jwtTokenExpiry, user };
  }

  @Mutation(returns => User)
  async signup(@Args('userCreateInput') userCreateInput: UserCreateInput) {
    const errors: any = {};
    const { email, name, username, password } = userCreateInput;
    if (password.length < 6) {
      errors.password = `Password must be at least 6 characters`;
    }

    const emailExists = await this.userService.exists({ email });
    if (emailExists) {
      errors.email = `Email ${email} is already in use`;
    }

    if (username) {
      const usernameExists = await this.userService.exists({ username });
      if (usernameExists) {
        errors.username = `Username ${username} is already in use`;
      }
    }

    if (this.appService.hasValidationErrors(errors)) {
      this.appService.throwValidationErrors('signup', errors);
    }
    const user = await this.userService.create({
      email,
      name,
      username,
      password,
    });
    try {
      await this.mailService.sendConfirmationEmail(user.email, user.id);
    } catch (error) {
      handleInternalError(error);
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
      handleInternalError(error);
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
      handleInternalError(error);
    }
    return true;
  }
}
