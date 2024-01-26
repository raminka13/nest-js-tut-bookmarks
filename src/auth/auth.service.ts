import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    try {
      //Password Gen
      const hash = await argon.hash(dto.password);
      //User push to DB
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      //Return New User
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('User already exists');
        }
      }
    }
  }

  async signin(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('Incorrect Credentials 1');

    const passCompare = await argon.verify(user.hash, dto.password);

    if (!passCompare) throw new ForbiddenException('Incorrect Credentials 2');

    delete user.hash;
    return user;
  }
}
