import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateAdminDto } from './dto/create-admin.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { ILike, Repository } from 'typeorm';
import * as argon2 from 'argon2';
import { UserStatus } from './enums/user-status.dto';
import { UserRole } from './enums/user-role.dto';
import { CreateDeliveryDto } from './dto/create-delivery.dto';
import { MailerService } from '@nestjs-modules/mailer';
import { LoginAdmin } from './dto/login-admin.dto';
import { JwtService } from '@nestjs/jwt';
import { VerifyOtp } from './dto/verify-otp.dto';
import { PaginationDto } from './dto/pagination.dto';
import { SearchDto } from './dto/search-dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private repo: Repository<User>,
    private readonly mailerService: MailerService,
    private jwtService: JwtService,
  ) {}

  async createAdmin({ email, password }: CreateAdminDto) {
    const userExists = await this.repo.findOneBy({ email });
    if (userExists) {
      throw new BadRequestException('User already exists with this email');
    }
    const hash = await argon2.hash(password);

    const user = this.repo.create({
      email,
      password: hash,
      status: UserStatus.ACTIVE,
      role: UserRole.ADMIN,
    });
    await this.repo.save(user);

    return 'Admin Account Created Successfully.';
  }

  async createDelivery({
    email,
    password,
    adress,
    dateOfBirth,
    carModel,
    licensePlate,
    carColor,
  }: CreateDeliveryDto) {
    const userExists = await this.repo.findOneBy({ email });
    if (userExists) {
      throw new BadRequestException('User already exists with this email');
    }
    const hash = await argon2.hash(password);

    const user = this.repo.create({
      email,
      password: hash,
      role: UserRole.DELIVERY,
      adress,
      dateOfBirth,
      carModel,
      licensePlate,
      carColor,
    });

    await this.repo.save(user);
    return 'Delivery created successfully.';
  }

  async loginAdmin({ email, password }: LoginAdmin) {
    const user = await this.repo.findOne({ where: { email } });
    if (!user) {
      throw new BadRequestException('User do not exists');
    }

    const passwordMatches = await argon2.verify(user.password, password);

    if (!passwordMatches) {
      throw new BadRequestException('Password is incorrect');
    }

    if (user.role === UserRole.DELIVERY) {
      throw new UnauthorizedException('Access denied');
    }

    return await this.getTokens(user.id, user.role);
  }

  async loginDelivery({ email, password }: LoginAdmin) {
    const user = await this.repo.findOne({ where: { email } });
    if (!user) {
      throw new BadRequestException('User do not exists');
    }

    const passwordMatches = await argon2.verify(user.password, password);

    if (!passwordMatches) {
      throw new BadRequestException('Password is incorrect');
    }

    if (user.role === UserRole.ADMIN) {
      throw new UnauthorizedException('Access denied');
    }

    if (user.status === UserStatus.INACTIVE) {
      throw new UnauthorizedException('Access denied');
    }

    if (user.status === UserStatus.PENDING) {
      const otpCode = this.generateOTP();

      const otpCodeExpireDate = new Date();

      otpCodeExpireDate.setMinutes(otpCodeExpireDate.getMinutes() + 1);

      this.sendVerificationEmail(user.email, otpCode);

      user.otp = otpCode;
      user.otpCodeExpireDate = otpCodeExpireDate;

      await this.repo.save(user);

      return {
        status: UserStatus.PENDING,
        access_token: null,
        refresh_token: null,
      };
    }

    const tokens = await this.getTokens(user.id, user.role);

    const response = { status: user.status, ...tokens };

    return response;
  }

  async getTokens(userId: number, role?: string) {
    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          role,
        },
        {
          secret: `${process.env.JWT_ACCESS_SECRET}`,
          expiresIn: '7d',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
        },
        {
          secret: `${process.env.JWT_REFRESH_SECRET}`,
          expiresIn: '30d',
        },
      ),
    ]);

    return {
      access_token,
      refresh_token,
    };
  }

  async sendVerificationEmail(email: string, otpCode: string) {
    await this.mailerService.sendMail({
      to: email,
      from: 'bengoudifa.contact@gmail.com',
      subject: 'OTP Verification',
      html: `<h3>Your OTP code is: ${otpCode}. This code will expire in 3 minutes.</h3>`,
    });
  }

  async verifyOtpDelivery({ code, email }: VerifyOtp) {
    const user = await this.repo.findOne({ where: { email } });

    if (!user || user.otp !== code || user.otpCodeExpireDate < new Date()) {
      throw new BadRequestException('Otp code expired');
    }

    user.status = UserStatus.ACTIVE;

    await this.repo.save(user);
    return 'Account Verified';
  }

  async getAllDeliveryUsers(
    { page, limit }: PaginationDto,
    { keyword }: SearchDto,
  ) {
    const skip = (page - 1) * limit;

    const [users, totalCount] = await this.repo.findAndCount({
      skip,
      take: limit,
      where: [
        {
          role: UserRole.DELIVERY,
          email: ILike(`%${keyword}%`),
          carModel: ILike(`%${keyword}%`),
          licensePlate: ILike(`%${keyword}%`),
          carColor: ILike(`%${keyword}%`),
          adress: ILike(`%${keyword}%`),
        },
      ],
    });

    const totalPages = Math.ceil(totalCount / limit);
    const hasNextPage = page < totalPages;

    return {
      items: users,
      totalCount,
      currentPage: page,
      totalPages,
      hasNextPage,
    };
  }

  async findOne(id: number) {
    const user = await this.repo.findOne({ where: { id } });

    if (!user) {
      throw new NotFoundException('user not found');
    }
    return user;
  }

  async updateStatusDelivery(userId: number, status: UserStatus) {
    const user = await this.findOne(userId);

    user.status = status;

    return await this.repo.save(user);
  }

  async refreshAccessToken(id: number) {
    const user = await this.findOne(id);
    if (!user) {
      throw new BadRequestException('bad token');
    }
    return await this.getTokens(user.id, user.role);
  }

  generateOTP(): string {
    return this.generateRandomNumber();
  }

  generateRandomNumber() {
    const min = 100000;
    const max = 999999;

    const randomNumber = Math.floor(Math.random() * (max - min + 1)) + min;
    return randomNumber.toString();
  }
}
