import { ArgsType, Field } from 'type-graphql';

@ArgsType()
export class ChangePasswordArgs {
  @Field()
  password: string;

  @Field()
  currentPassword: string;
}
