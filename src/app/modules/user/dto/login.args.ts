import { IsEmail, IsOptional } from 'class-validator';
import { ArgsType, Field } from 'type-graphql';

@ArgsType()
export class LoginArgs {
  @Field(type => String)
  @IsEmail()
  email: string;

  @Field(type => String, { nullable: true })
  @IsOptional()
  password?: string;

  @Field(type => String, { nullable: true })
  @IsOptional()
  otp?: string;
}
