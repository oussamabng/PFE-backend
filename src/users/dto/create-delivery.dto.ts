import { InputType, Field } from '@nestjs/graphql';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

@InputType()
export class CreateDeliveryDto {
  @IsEmail()
  @Field(() => String)
  email: string;

  @IsNotEmpty()
  @IsString()
  @Field(() => String)
  password: string;

  phoneNumber?: string;
  adress?: string;
  dateOfBirth?: Date;
  carModel?: string;
  licensePlate?: string;
  carColor?: string;
}
