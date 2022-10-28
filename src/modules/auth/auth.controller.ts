import {
  Controller,
  Post,
  Get,
  HttpCode,
  Body,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { AuthLoginDto } from './dto/auth-login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtRefreshTokenGuard } from './guards/jwt-refresh-token.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly service: AuthService) {}
  @Post()
  @HttpCode(200)
  async login(
    @Body() authLoginDto: AuthLoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { refreshToken, accessToken } = await this.service.login(
      authLoginDto,
    );
    res.cookie('refresh_token', refreshToken, {
      maxAge: 1000 * 60 * 60 * 7,
      httpOnly: true,
    });
    res.cookie('access_token', accessToken, {
      maxAge: 1000 * 60 * 10,
      httpOnly: true,
    });
  }

  @Get('refresh')
  async refreshAccessToken(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const cookies = req.cookies ?? req.signedCookies;
    const refreshToken = cookies.refresh_token;
    if (!cookies.access_token) {
      const accessToken = await this.service.updateAccessToken(refreshToken);
      res.cookie('access_token', accessToken, {
        maxAge: 1000 * 60 * 10,
        httpOnly: true,
      });
    }
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard, JwtRefreshTokenGuard)
  @HttpCode(200)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const { userId } = req.user as { userId: string };
    await this.service.logout(userId);
    // Clear cookies
    res.cookie('access_token', null);
    res.cookie('refresh_token', null);
  }
}
