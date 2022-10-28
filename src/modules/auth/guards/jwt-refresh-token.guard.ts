import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtRefreshTokenGuard implements CanActivate {
  constructor(private authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const { user }: { user: { userId: string } } = request;
    const refreshToken = request.cookies?.refresh_token;
    if (!refreshToken) throw new UnauthorizedException();
    await this.authService.validateRefreshToken(user.userId, refreshToken);
    return true;
  }
}
