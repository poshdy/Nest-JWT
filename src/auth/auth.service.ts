import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types/types';
@Injectable()
export class AuthService {
  constructor(private readonly dataService: PrismaService) {}

  async hashData(data: string) {
    return await bcrypt.hash(data, 10);
  }
  async signUp(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password);
    await this.dataService.user.create({
      data: {
        email: dto.email,
        hash,
      },
    });
    const access_token = '';
    const refresh_token = '';
    return await {
      access_token,
      refresh_token,
    };
  }
  signIn(dto: AuthDto) {
    console.log(dto);
  }
  signOut() {}
  refreshToken() {}
}
