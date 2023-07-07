import { UserStatus } from '../enums/user-status.dto';
import { Expose } from 'class-transformer';

export class UserDto {
  @Expose()
  id: number;

  @Expose()
  email: string;

  @Expose()
  status: UserStatus;

  @Expose()
  phoneNumber: string;

  @Expose()
  adress: string;

  @Expose()
  dateOfBirth: Date;

  @Expose()
  carModel: string;

  @Expose()
  licensePlate: string;

  @Expose()
  otp: string;

  @Expose()
  carColor: string;

  @Expose()
  createdAt: Date;

  @Expose()
  updatedAt: Date;
}
