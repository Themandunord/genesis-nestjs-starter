import { GqlModuleOptions, GqlOptionsFactory } from '@nestjs/graphql';
import { ApolloError } from 'apollo-server-express';
import { join } from 'path';
import { v4 } from 'uuid';
import { GraphQLError } from 'graphql/error';
import dotenv from 'dotenv';

dotenv.config();
export class GraphqlOptions implements GqlOptionsFactory {
  createGqlOptions(): Promise<GqlModuleOptions> | GqlModuleOptions {
    const origin = process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(',')
      : 'http://localhost:3000';

    return {
      cors: {
        origin,
        credentials: true,
      },
      autoSchemaFile: 'schema.gql',
      path: '/',
      installSubscriptionHandlers: true,
      playground: process.env.NODE_ENV === 'development',
      context: ({ req, res }: any) => ({
        req,
        res,
      }),
      formatError: (error: GraphQLError) => {
        if (error.originalError instanceof ApolloError) {
          return error;
        }

        const errId = v4();
        console.log('errId: ', errId);
        console.log(JSON.stringify(error, null, 2));

        return new GraphQLError(`Internal Error: ${errId}`);
      },
      definitions: {
        path: join(process.cwd(), 'src/graphql.ts'),
        outputAs: 'class',
      },
    };
  }
}
