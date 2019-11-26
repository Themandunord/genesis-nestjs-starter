import { Time } from './time';
import { Field, ObjectType } from 'type-graphql';

@ObjectType()
export class CPU {
  @Field()
  model: string;

  @Field()
  speed: number;

  @Field()
  times: Time;
}
