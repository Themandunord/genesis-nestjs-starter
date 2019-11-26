import { Module, Injectable } from '@nestjs/common';
// import { ExpressSessionMiddleware } from '@nest-middlewares/express-session';
// import connectRedis from 'connect-redis';
// import expressSession from 'express-session';

// import { HelmetMiddleware } from '@nest-middlewares/helmet';
// import { CsurfMiddleware } from '@nest-middlewares/csurf';

import { GraphQLModule } from '@nestjs/graphql';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigService } from 'nestjs-config';
import { RedisModule } from 'nestjs-redis';
import { ConfigModule } from 'nestjs-config';
import { resolve } from 'path';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { GraphqlOptions } from './graphql.options';
import { MailModule } from './../core/mailer/mailer.module';
// import { AuthModule } from './modules/auth/auth.module';
// import { CommonModule } from './modules/common/common.module';
// import { UserModule } from './modules/user';
// import { NodeModule } from './modules/node/node.module';

import { CommonModule } from '@modules/common';
import { AuthModule } from '@modules/auth';
import { UserModule } from '@modules/user';
import { NodeModule } from '@modules/node';

@Module({
  imports: [
    // BootstrapModule,
    ConfigModule.load(resolve(__dirname, '../config', '**/!(*.d).{ts,js}')),
    GraphQLModule.forRootAsync({
      useClass: GraphqlOptions,
    }),
    RedisModule.forRootAsync({
      useFactory: (configService: ConfigService) => configService.get('redis'),
      inject: [ConfigService],
    }),
    TypeOrmModule.forRootAsync({
      useFactory: (config: ConfigService) => config.get('database'),
      inject: [ConfigService],
    }),
    CommonModule,
    AuthModule,
    UserModule,
    NodeModule,
    MailModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
@Injectable()
export class AppModule {}
