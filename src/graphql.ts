
/** ------------------------------------------------------
 * THIS FILE WAS AUTOMATICALLY GENERATED (DO NOT MODIFY)
 * -------------------------------------------------------
 */

/* tslint:disable */
export class UserCreateInput {
    email: string;
    password?: string;
    name: string;
    username?: string;
    googleId?: string;
    facebookId?: string;
    twitterId?: string;
    githubId?: string;
    imageUrl?: string;
    role?: string;
    status?: string;
    lastLoginAt?: DateTime;
}

export class AuthPayload {
    token: string;
    tokenExpiry: DateTime;
    user: User;
}

export class CPU {
    model: string;
    speed: number;
    times: Time;
}

export abstract class IMutation {
    abstract login(email: string, password?: string, otp?: string): AuthPayload | Promise<AuthPayload>;

    abstract sendLoginOTP(email: string): boolean | Promise<boolean>;

    abstract loginWithOTP(email: string, password?: string, otp?: string): AuthPayload | Promise<AuthPayload>;

    abstract logoutfromAllDevices(): boolean | Promise<boolean>;

    abstract logout(): boolean | Promise<boolean>;

    abstract forgotPassword(email: string): boolean | Promise<boolean>;

    abstract changePassword(password: string, currentPassword: string): boolean | Promise<boolean>;

    abstract resetPassword(password: string, token: string): boolean | Promise<boolean>;

    abstract refreshToken(): AuthPayload | Promise<AuthPayload>;

    abstract signup(userCreateInput: UserCreateInput): User | Promise<User>;

    abstract confirm(token: string): boolean | Promise<boolean>;

    abstract resendConfirm(email: string): boolean | Promise<boolean>;
}

export abstract class IQuery {
    abstract me(): User | Promise<User>;

    abstract cpus(): CPU[] | Promise<CPU[]>;
}

export class Time {
    user: number;
    nice: number;
    sys: number;
    idle: number;
    irq: number;
}

export class User {
    id: string;
    name: string;
    username?: string;
    email: string;
    phone?: string;
    bio?: string;
    googleId?: string;
    facebookId?: string;
    twitterId?: string;
    githubId?: string;
    imageUrl?: string;
    status: string;
    role: string;
    tokenVersion: number;
    lastLoginAt?: string;
    createdAt?: DateTime;
    updatedAt?: DateTime;
}

export type DateTime = any;
