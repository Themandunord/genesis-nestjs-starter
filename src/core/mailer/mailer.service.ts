
import { ISendMailOptions, MailerService } from '@nest-modules/mailer';
import { Injectable } from '@nestjs/common';
import { readFile } from 'fs';
import { each } from 'lodash';
import { ConfigService } from 'nestjs-config';
import { RedisService } from 'nestjs-redis';
import { getTestMessageUrl, SentMessageInfo } from 'nodemailer';
import { join } from 'path';
import randomize from 'randomatic';
import { promisify } from 'util';
import { v4 } from 'uuid';
import {
  REDIS_CONFIRM_TOKEN_PREFIX,
  REDIS_FORGOT_PASSWORD_TOKEN_PREFIX,
  REDIS_LOGIN_OTP_PREFIX,
} from '@app/constants';

@Injectable()
export class MailService {
  constructor(
    private readonly mailerService: MailerService,
    private readonly config: ConfigService,
    private readonly redisService: RedisService,
  ) {
    this.config = config;
  }

  private render(html, context = {}) {
    let content = html;
    each(context, (value, key) => {
      content = content.replace(new RegExp(`#{${key}}`, 'g'), value);
    });
    return content;
  }
  private async renderTemplate(template, context = {}) {
    const templateDir = this.config.get('mailer').templateDir;
    const templatePath = join(
      __dirname, '..', '..',
      templateDir || './public/templates',
      `${template}.html`,
    );
    try {
      const readFileAsync = promisify(readFile);
      const content = await readFileAsync(templatePath, {
        encoding: 'utf8',
      });
      return this.render(content, context);
    } catch (error) {
      console.log(error);
      return null;
    }
  }

  async sendEmail(options: ISendMailOptions): Promise<SentMessageInfo | null> {
    try {
      const info: SentMessageInfo = await this.mailerService.sendMail(options);
      console.log('Message sent: %s', info.messageId);
      // Preview only available when sending through an Ethereal account
      console.log('Preview URL: %s', getTestMessageUrl(info));
      return info;
    } catch (e) {
      console.error(e);
    }
    return null;
  }

  async sendConfirmationEmail(
    email: string,
    id: string,
  ): Promise<SentMessageInfo | null> {
    try {
      const token = v4();
      const url = `${this.config.get('api').confirmUrl()}?token=${token}`;
      const html = await this.renderTemplate('confirm', { url });
      const options = {
        to: email, // sender address
        from: 'noreply@genesis.com', // list of receivers
        subject: 'Welcome to Genesis ✔', // Subject line
        html, // HTML body content
      };
      const info = await this.sendEmail(options);
      const client = this.redisService.getClient();
      client.set(REDIS_CONFIRM_TOKEN_PREFIX + token, id, 'ex', 60 * 60 * 24);
      return info;
    } catch (e) {
      console.error(e);
    }
    return null;
  }

  async sendForgotPasswordEmail(
    email: string,
    id: string,
  ): Promise<SentMessageInfo | null> {
    try {
      const token = v4();
      const url = `${this.config.get('api').forgetUrl()}?token=${token}`;
      const html = await this.renderTemplate('forgot', { url });
      const options = {
        to: email, // sender address
        from: 'noreply@genesis.com', // list of receivers
        subject: 'Password assistance for Genesis ✔', // Subject line
        html, // HTML body content
      };
      const info = await this.sendEmail(options);
      const client = this.redisService.getClient();
      client.set(
        REDIS_FORGOT_PASSWORD_TOKEN_PREFIX + token,
        id,
        'ex',
        60 * 60 * 24,
      );
      return info;
    } catch (e) {
      console.error(e);
    }
    return null;
  }

  async sendOTPEmail(
    email: string,
    id: string,
    subject: string = '',
  ): Promise<SentMessageInfo | null> {
    try {
      const otp = randomize('0', 6);
      const html = await this.renderTemplate('otp', { otp, subject });
      const options = {
        to: email, // sender address
        from: 'noreply@genesis.com', // list of receivers
        subject, // Subject line
        html, // HTML body content
      };
      const info = await this.sendEmail(options);
      const client = this.redisService.getClient();
      client.set(REDIS_LOGIN_OTP_PREFIX + email + otp, id, 'ex', 60 * 60 * 24);
      return info;
    } catch (e) {
      console.error(e);
    }
    return null;
  }
}
