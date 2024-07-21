import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';

import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'refresh-jwt',
) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.REFRESH,
      passReqToCallback: true,
    });
  }
  async validate(request: Request, payload: any) {
    const refresh = request.get('authorization').replace('Bearer', '').trim();
    return {
      ...payload,
      refresh,
    };
  }
}
