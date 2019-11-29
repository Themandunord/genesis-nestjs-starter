// import { AuthModule } from '@modules/auth';
// import { CommonModule } from '@modules/common';
// import { NodeModule } from '@modules/node';
// import { UserModule } from '@modules/user';
import { Injectable, Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from 'nestjs-config';
import { RedisModule } from 'nestjs-redis';
import { resolve } from 'path';
import { MailModule } from './../core/mailer/mailer.module';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { GraphqlOptions } from './graphql.options';
import { AuthModule } from './modules/auth/auth.module';
import { CommonModule } from './modules/common/common.module';
import { NodeModule } from './modules/node/node.module';
import { UserModule } from './modules/user';

@Module({
  imports: [
    // BootstrapModule,
    ConfigModule.load(resolve(__dirname, '../config', '**/!(*.d).{ts,js}')),
    GraphQLModule.forRootAsync({
      useClass: GraphqlOptions,
    }),
    JwtModule.registerAsync({
      useFactory: (config: ConfigService) => config.get('jwt').accessToken,
      inject: [ConfigService],
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
