import { UserWhereInput } from './dto/user.where.input';
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

import { CryptoService } from '../auth/crypto.service';
import User from './models/user.entity';
import { UserCreateInput } from './dto/user.create.input';
import { UserUpdateInput } from './dto/user.update.input';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly cryptoService: CryptoService,
  ) {}

  public async update(user: UserUpdateInput, where: UserWhereInput) {
    const result = await this.userRepository.update(where, user);
    return result;
  }

  public async find(where: UserWhereInput) {
    return await this.userRepository.find({ where });
  }

  public async findOne(where: UserWhereInput) {
    const user = await this.userRepository.findOne({ where });
    return user;
  }

  public async exists(where: UserWhereInput) {
    const user = await this.userRepository.findOne({ where });
    return user ? true : false;
  }

  public async encrypt(password: string) {
    return await this.cryptoService.hashPassword(password);
  }

  public async create(user: UserCreateInput) {
    let password = user.password;
    if (password) {
      password = await this.cryptoService.hashPassword(user.password);
    }

    const newUser = await this.userRepository.create({
      ...user,
      password,
    });
    await newUser.save();
    return newUser;
  }
}
