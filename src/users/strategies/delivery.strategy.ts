import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UsersService } from 'src/users/users.service';
import { UserRole } from '../enums/user-role.dto';
import { UserStatus } from '../enums/user-status.dto';

type JwtPayload = {
  sub: number;
};

@Injectable()
export class DeliveryStrategy extends PassportStrategy(Strategy, 'delivery') {
  constructor(private userService: UsersService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_ACCESS_SECRET,
      ignoreExpiration: false,
    });
  }

  async validate(payload: JwtPayload) {
    const userId = payload.sub ? payload.sub : null;

    const user = await this.userService.findOne(userId);

    if (
      user?.id === userId &&
      user?.role === UserRole.DELIVERY &&
      user?.status === UserStatus.ACTIVE
    ) {
      return { userId };
    } else return false;
  }
}
