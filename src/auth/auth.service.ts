import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types/types';
import { JwtService } from '@nestjs/jwt';
@Injectable()
export class AuthService {
  constructor(
    private readonly dataService: PrismaService,
    private readonly jwtService: JwtService,
  ) {}
  async signUp(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password);
    const user = await this.dataService.user.create({
      data: {
        email: dto.email,
        hash,
      },
    });
    const { access_token, refresh_token } = await this.generateTokens(
      user.id,
      user.email,
    );
    await this.updateRefreshToken(user.id, refresh_token);
    return {
      access_token,
      refresh_token,
    };
  }
  async signIn(dto: AuthDto) {
    const user = await this.dataService.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('access denied');
    const isPassMatch = await bcrypt.compare(dto.password, user.hash);
    if (!isPassMatch) throw new ForbiddenException('access denied');
    const { access_token, refresh_token } = await this.generateTokens(
      user.id,
      user.email,
    );
    await this.updateRefreshToken(user.id, refresh_token);
    return {
      access_token,
      refresh_token,
    };
  }
  async signOut(userId: number) {
    await this.dataService.user.updateMany({
      data: {
        hashRt: '',
      },
      where: {
        hashRt: {
          not: null,
        },
        id: userId,
      },
    });
  }
  async refreshToken(userId: number, refresh: string) {
    const user = await this.dataService.user.findUnique({
      where: { id: userId },
    });
    if (!user) throw new ForbiddenException('access denied');
    const isRtMatch = await bcrypt.compare(refresh, user.hashRt);
    if (!isRtMatch) throw new ForbiddenException('access denied');
    const { access_token, refresh_token } = await this.generateTokens(
      user.id,
      user.email,
    );
    await this.updateRefreshToken(user.id, refresh_token);
    return {
      access_token,
      refresh_token,
    };
  }
  async generateTokens(userId: number, email: string) {
    const user = {
      userId,
      email,
    };
    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(user, {
        expiresIn: 60 * 15, // 15 minute
        secret: process.env.SECRET,
      }),
      this.jwtService.signAsync(user, {
        expiresIn: 60 * 60 * 24 * 10, // 10 days
        secret: process.env.REFRESH,
      }),
    ]);

    return {
      access_token,
      refresh_token,
    };
  }
  async hashData(data: string) {
    return await bcrypt.hash(data, 10);
  }
  async updateRefreshToken(userId: number, refreshToken: string) {
    const hashedRt = await this.hashData(refreshToken);
    await this.dataService.user.update({
      data: {
        hashRt: hashedRt,
      },
      where: {
        id: userId,
      },
    });
  }
}
