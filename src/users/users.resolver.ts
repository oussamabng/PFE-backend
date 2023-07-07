import { Resolver, Mutation, Args, Query } from '@nestjs/graphql';
import { UsersService } from './users.service';
import { CreateAdminDto } from './dto/create-admin.dto';
import { CreateDeliveryDto } from './dto/create-delivery.dto';
import { User } from './entities/user.entity';
import { LoginAdmin } from './dto/login-admin.dto';
import { ResponseTokenDto } from './dto/response-token.dto';
import { DeliveryResponseDto } from './dto/delivery-response.dto';
import { VerifyOtp } from './dto/verify-otp.dto';
import { CurrentUserId } from './interceptors/current-user-id.decorator';
import { UseGuards } from '@nestjs/common';
import { RefreshGuard } from './guards/refresh.guard';
import { PaginationDto } from './dto/pagination.dto';
import { ResponseUserDto } from './dto/response-user.dto';
import { UserStatus } from './enums/user-status.dto';
import { AdminGuard } from './guards/admin.guard';
import { SearchDto } from './dto/search-dto';

@Resolver()
export class UsersResolver {
  constructor(private readonly usersService: UsersService) {}

  @Mutation(() => String)
  createAdmin(@Args('input') createAdminDto: CreateAdminDto) {
    return this.usersService.createAdmin(createAdminDto);
  }

  @Mutation(() => String)
  createDelivery(@Args('input') createDeliveryDto: CreateDeliveryDto) {
    return this.usersService.createDelivery(createDeliveryDto);
  }

  @Mutation(() => ResponseTokenDto)
  loginAdmin(@Args('input') loginAdmin: LoginAdmin) {
    return this.usersService.loginAdmin(loginAdmin);
  }

  @Mutation(() => DeliveryResponseDto)
  loginDelivery(@Args('input') loginAdmin: LoginAdmin) {
    return this.usersService.loginDelivery(loginAdmin);
  }

  @Mutation(() => String)
  verifyOtpDelivery(@Args('input') verifyOtp: VerifyOtp) {
    return this.usersService.verifyOtpDelivery(verifyOtp);
  }

  @UseGuards(RefreshGuard)
  @Mutation(() => ResponseTokenDto)
  refreshToken(@CurrentUserId() userId: number) {
    return this.usersService.refreshAccessToken(userId);
  }

  @UseGuards(AdminGuard)
  @Query(() => ResponseUserDto)
  getAllDeliveryUsers(
    @Args('pagination') paginationDto: PaginationDto,
    @Args('search') searchDto: SearchDto,
  ) {
    return this.usersService.getAllDeliveryUsers(paginationDto, searchDto);
  }

  @UseGuards(AdminGuard)
  @Mutation(() => User)
  updateStatusDelivery(
    @Args('userId') userId: number,
    @Args('status') status: UserStatus,
  ) {
    return this.usersService.updateStatusDelivery(userId, status);
  }

  @Query(() => String)
  helloWorld() {
    return 'Hello';
  }
}
