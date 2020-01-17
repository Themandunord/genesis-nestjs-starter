import { Field, ID, ObjectType } from 'type-graphql';
import GraphQLJSON from 'graphql-type-json';

import {
  BaseEntity,
  Column,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
  CreateDateColumn,
} from 'typeorm';

@ObjectType()
@Entity('user', { schema: 'public' })
@Index('user_email_key', ['email'], { unique: true })
@Index('UQ_b7a5e4a3b174e954b2dabf2ef9e', ['email'], { unique: true })
@Index('user_facebookId_key', ['facebookId'], { unique: true })
@Index('UQ_89635bfc77b8768544d5c82a7c4', ['facebookId'], { unique: true })
@Index('UQ_7dfc7794e80610b83c5cf5d8348', ['githubId'], { unique: true })
@Index('user_githubId_key', ['githubId'], { unique: true })
@Index('UQ_7c9f5f0d759b84373b901768d4d', ['googleId'], { unique: true })
@Index('user_googleId_key', ['googleId'], { unique: true })
@Index('UQ_99acedb51629efbe55bcad471bb', ['phone'], { unique: true })
@Index('user_phone_key', ['phone'], { unique: true })
@Index('UQ_cf64c24776ea5db1f17d345c399', ['twitterId'], { unique: true })
@Index('user_twitterId_key', ['twitterId'], { unique: true })
@Index('user_username_key', ['username'], { unique: true })
@Index('UQ_b67337b7f8aa8406e936c2ff754', ['username'], { unique: true })
export class User extends BaseEntity {
  @Field(_ => ID)
  @PrimaryGeneratedColumn('uuid')
  readonly id: string;

  @Field()
  @Column('text', {
    nullable: false,
    name: 'name',
  })
  name: string;

  @Field(_ => String, { nullable: true })
  @Column('text', {
    nullable: true,
    unique: true,
    name: 'username',
  })
  username?: string | null;

  @Field()
  @Column('text', {
    nullable: false,
    unique: true,
    name: 'email',
  })
  email: string;

  @Column('text', {
    nullable: false,
    name: 'password',
  })
  password: string;

  @Field(_ => String, { nullable: true })
  @Column('text', {
    nullable: true,
    unique: true,
    name: 'phone',
  })
  phone?: string | null;

  @Field(_ => GraphQLJSON, { nullable: true })
  @Column('jsonb', {
    name: 'bio',
    nullable: true,
    default: () => 'jsonb_build_object()',
  })
  bio: object | null;

  @Field(_ => String, { nullable: true })
  @Column('text', {
    nullable: true,
    name: 'bio',
  })
  bio?: string | null;

  @Field(_ => String, { nullable: true })
  @Column('text', {
    nullable: true,
    unique: true,
    name: 'google_id',
  })
  googleId?: string | null;

  @Field(_ => String, { nullable: true })
  @Column('text', {
    nullable: true,
    unique: true,
    name: 'facebook_id',
  })
  facebookId?: string | null;

  @Field(_ => String, { nullable: true })
  @Column('text', {
    nullable: true,
    unique: true,
    name: 'twitter_id',
  })
  twitterId?: string | null;

  @Field(_ => String, { nullable: true })
  @Column('text', {
    nullable: true,
    unique: true,
    name: 'github_id',
  })
  githubId?: string | null;

  @Field(_ => String, { nullable: true })
  @Column('text', {
    nullable: true,
    name: 'image_url',
  })
  imageUrl?: string | null;

  @Field()
  @Column('text', {
    nullable: false,
    default: () => 'verification',
    name: 'status',
  })
  status?: string;

  @Field()
  @Column('text', {
    nullable: true,
    default: () => 'user',
    name: 'role',
  })
  role?: string;

  @Field()
  @Column('integer', {
    nullable: true,
    default: () => 1,
    name: 'token_version',
  })
  tokenVersion?: number;

  @Field(_ => String, { nullable: true })
  @Column('timestamp with time zone', {
    nullable: true,
    name: 'last_login_at',
  })
  lastLoginAt?: Date | null;

  @Field(_ => Date, { nullable: true })
  @CreateDateColumn({
    nullable: true,
    default: () => 'now()',
    name: 'created_at',
  })
  createdAt: Date | null;

  @Field(_ => Date, { nullable: true })
  @UpdateDateColumn({
    nullable: true,
    name: 'updated_at',
  })
  updatedAt: Date | null;
}

export default User;
