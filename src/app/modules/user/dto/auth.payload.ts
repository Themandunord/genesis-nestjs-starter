import { Field, ObjectType } from 'type-graphql';
import User from '../models/user.entity';

@ObjectType()
export class AuthPayload {
  @Field()
  token: string;

  @Field()
  tokenExpiry: Date;

  @Field(_ => User, { nullable: false })
  user: User;
}
