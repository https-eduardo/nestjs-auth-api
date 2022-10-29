import { Injectable } from '@nestjs/common';
import { TokenType } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class TokensService {
  constructor(private prisma: PrismaService) { }

  async create(userId: string, type: TokenType) {
    return await this.prisma.token.create({
      data: { userId, type },
    });
  }

  async findOne(id: string) {
    return await this.prisma.token.findUnique({
      where: { id },
    });
  }

  async remove(id: string) {
    return await this.prisma.token.delete({ where: { id } });
  }
}
