import {
  Injectable,
  UnauthorizedException,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import { UsersService } from '../users/users.service';
import { AuthLoginDto } from './dto/auth-login.dto';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async login(authLoginDto: AuthLoginDto) {
    const user = await this.validateUser(authLoginDto);

    const refreshToken = this.jwtService.sign({ userId: user.id });
    await this.usersService.setRefreshToken(user.id, refreshToken);

    const accessToken = this.generateAccessToken(user);

    return {
      refreshToken,
      accessToken,
    };
  }
  async logout(id: string) {
    const user = await this.usersService.setRefreshToken(id, null);
    if (!user) throw new NotFoundException();

    return user;
  }

  private async validateUser(authLoginDto: AuthLoginDto) {
    const { email, password } = authLoginDto;
    const user = await this.usersService.findByEmail(email);

    if (!(await this.usersService.validateHash(password, user.password)))
      throw new UnauthorizedException();

    return user;
  }

  async updateAccessToken(refreshToken: string) {
    const data = this.jwtService.decode(refreshToken) as { userId: string };
    if (!data || !data.userId) throw new NotFoundException();
    const user = await this.usersService.findById(data.userId);

    if (!user.refreshToken) throw new BadRequestException();
    const isValidRefreshToken = await this.usersService.validateHash(
      refreshToken,
      user.refreshToken,
    );
    if (!isValidRefreshToken) throw new UnauthorizedException();

    const accessToken = this.generateAccessToken(user);

    return accessToken;
  }
  private generateAccessToken(user: User) {
    const payload = {
      userId: user.id,
      username: user.username,
      email: user.email,
    };
    return this.jwtService.sign(payload, { expiresIn: '10m' });
  }

  async validateRefreshToken(userId: string, refreshToken: string) {
    const user = await this.usersService.findById(userId);
    if (!user) throw new NotFoundException();
    if (
      !user.refreshToken ||
      !(await this.usersService.validateHash(refreshToken, user.refreshToken))
    )
      throw new UnauthorizedException();

    return user;
  }
}
