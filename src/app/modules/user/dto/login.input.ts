import { IsEmail, IsOptional } from 'class-validator';
import { Field, InputType } from 'type-graphql';

@InputType()
export class LoginInput {
  @Field()
  @IsEmail()
  email: string;

  @Field({ nullable: true })
  @IsOptional()
  password?: string;

  @Field({ nullable: true })
  @IsOptional()
  otp?: string;
}
