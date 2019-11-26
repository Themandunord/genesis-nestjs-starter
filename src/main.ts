import 'module-alias/register';
import { config } from 'dotenv';
config();

import { NestFactory } from '@nestjs/core';
import compression from 'compression';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { AppModule } from '@app/app.module';
import cookieParser from 'cookie-parser';
// import session from 'express-session';
// import redis from 'redis';
// import connectRedis from 'connect-redis';
// import sessionConfig from '@config/session';
// import redisConfig from '@config/redis';

// const RedisStore = connectRedis(session);

// Startup
(async function bootstrap() {
  try {
    process.on('warning', e => console.warn(e.stack));
    const origin = process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(',')
      : 'http://localhost:3000';
    const app = await NestFactory.create(AppModule, {
      cors: {
        origin,
        credentials: true,
      },
    });
    app.use(compression());
    app.use(helmet());
    app.use(cookieParser());
    // app.enableCors();
    app.use(
      rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 1000, // limit each IP to 100 requests per windowMs
      }),
    );

    // const client = redis.createClient({
    //   host: redisConfig.host,
    //   port: redisConfig.port,
    //   password: redisConfig.password,
    //   db: redisConfig.db,
    //   prefix: redisConfig.keyPrefix,
    // });
    // app.use(
    //   session({
    //     store: new RedisStore({
    //       client,
    //     }),
    //     ...sessionConfig,
    //   }),
    // );
    await app.listen(parseInt(process.env.API_PORT, 10) || 4000);
    console.info(
      `Application started successfully on port ${parseInt(
        process.env.API_PORT,
        10,
      ) || 4000}`,
    );
  } catch (error) {
    console.error('error', error);
  }
})();
