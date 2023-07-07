import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersResolver } from './users.resolver';
import { User } from './entities/user.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MailerModule } from '@nestjs-modules/mailer';
import { JwtModule } from '@nestjs/jwt';
import { AdminStrategy } from './strategies/admin.strategy';
import { DeliveryStrategy } from './strategies/delivery.strategy';
import { RefreshStrategy } from './strategies/refresh.strategy';
import { PassportModule } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    JwtModule.register({}),
    PassportModule,
    MailerModule.forRoot({
      transport: {
        host: 'smtp.gmail.com',
        secure: true,
        port: 465,
        auth: {
          user: 'bengoudifa.contact@gmail.com',
          pass: 'wttfaqvgbhbaykob',
        },
      },
    }),
  ],
  providers: [
    ConfigService,
    UsersResolver,
    UsersService,
    AdminStrategy,
    DeliveryStrategy,
    RefreshStrategy,
  ],
})
export class UsersModule {}
