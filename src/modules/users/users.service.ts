import {
  Injectable,
  BadRequestException,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcryptjs';
import { ChangePasswordDto } from './dto/change-password.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { TokensService } from '../tokens/tokens.service';
import { TokenType } from '@prisma/client';
import { RecoveryPasswordDto } from './dto/recovery-password.dto';

@Injectable()
export class UsersService {
  constructor(
    private prisma: PrismaService,
    private tokensService: TokensService,
  ) {}

  async create(createUserDto: CreateUserDto) {
    const data = createUserDto;
    data.password = await bcrypt.hash(data.password, 8);
    const user = await this.prisma.user.create({ data });

    if (!user) throw new BadRequestException();
    const token = await this.tokensService.create(user.id, TokenType.CONFIRM);
    this.sendConfirmationMail(user.email, token.id);

    delete user.password;

    return user;
  }

  async changePassword(id: string, changePasswordDto: ChangePasswordDto) {
    const { password, newPassword } = changePasswordDto;
    const user = await this.findById(id);

    const passwordMatches = await this.validateHash(password, user.password);
    if (!passwordMatches) throw new ForbiddenException();
    const hashedPassword = await bcrypt.hash(newPassword, 8);

    const updatedUser = await this.prisma.user.update({
      where: { id },
      data: { password: hashedPassword, refreshToken: null },
    });

    if (!updatedUser) throw new BadRequestException();

    delete updatedUser.password;
    delete updatedUser.refreshToken;

    return updatedUser;
  }

  async findById(id: string) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException();

    return user;
  }

  async findByEmail(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new NotFoundException();

    return user;
  }

  async setRefreshToken(id: string, refreshToken: string | null) {
    // Hash the token to prevent user impersonation in a possible database leak
    if (refreshToken) refreshToken = await bcrypt.hash(refreshToken, 8);
    const user = await this.prisma.user.update({
      where: { id },
      data: { refreshToken },
    });
    if (!user) throw new NotFoundException();
    return user;
  }

  async requestRecovery(email: string) {
    const user = await this.findByEmail(email);
    const token = await this.tokensService.create(user.id, TokenType.RECOVERY);

    this.sendRecoveryMail(email, token.id);
    return {
      message: 'Recovery email have been send',
    };
  }

  async recoveryPassword(
    recoveryId: string,
    recoveryPasswordDto: RecoveryPasswordDto,
  ) {
    const { password } = recoveryPasswordDto;
    const token = await this.tokensService.findOne(recoveryId);
    if (token.type !== TokenType.RECOVERY) throw new BadRequestException();
    const user = await this.findById(token.userId);
    const hashedPassword = await bcrypt.hash(password, 8);
    await Promise.all([
      this.prisma.user.update({
        where: { id: user.id },
        data: {
          password: hashedPassword,
        },
      }),
      this.tokensService.remove(recoveryId),
    ]);
    return { message: 'Password recovery successfully.' };
  }

  async confirm(confirmationId: string) {
    const token = await this.tokensService.findOne(confirmationId);
    if (token.type !== TokenType.CONFIRM) throw new BadRequestException();
    const user = await this.findById(token.userId);
    await Promise.all([
      this.prisma.user.update({
        where: { id: user.id },
        data: {
          confirmed: true,
        },
      }),
      this.tokensService.remove(confirmationId),
    ]);
    return { message: 'User confirmed successfully.' };
  }

  private async sendConfirmationMail(email: string, tokenId: string) {}

  private async sendRecoveryMail(email: string, tokenId: string) {}

  async validateHash(content: string, hash: string) {
    return await bcrypt.compare(content, hash);
  }
}
