import { ArgsType, Field } from 'type-graphql';

@ArgsType()
export class ResetPasswordArgs {
  @Field()
  password: string;

  @Field()
  token: string;
}
