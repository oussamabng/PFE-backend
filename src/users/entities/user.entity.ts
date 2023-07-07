import {
  Column,
  Entity,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { UserRole } from '../enums/user-role.dto';
import { UserStatus } from '../enums/user-status.dto';
import {
  Field,
  HideField,
  ID,
  ObjectType,
  registerEnumType,
} from '@nestjs/graphql';

registerEnumType(UserRole, {
  name: 'UserRole',
});

registerEnumType(UserStatus, {
  name: 'UserStatus',
});

@Entity('user')
@ObjectType()
export class User {
  @Field(() => ID)
  @PrimaryGeneratedColumn()
  id: number;

  @Field(() => String)
  @Column({ unique: true })
  email: string;

  @HideField()
  @Column()
  password: string;

  @Field(() => UserRole)
  @Column({ type: 'enum', enum: UserRole, default: UserRole.DELIVERY })
  role: UserRole;

  @Field(() => UserStatus)
  @Column({ type: 'enum', enum: UserStatus, default: UserStatus.PENDING })
  status: UserStatus;

  @Field(() => String)
  @Column({ nullable: true })
  phoneNumber: string;

  @Field(() => String)
  @Column({ nullable: true })
  adress: string;

  @Field(() => Date)
  @Column({ nullable: true })
  dateOfBirth: Date;

  @Field(() => String)
  @Column({ nullable: true })
  carModel: string;

  @Field(() => String)
  @Column({ nullable: true })
  licensePlate: string;

  @Field(() => String)
  @Column({ nullable: true })
  otp: string;

  @Field(() => String)
  @Column({ nullable: true })
  otpCodeExpireDate: Date;

  @Field(() => String)
  @Column({ nullable: true })
  carColor: string;

  @Field(() => Date)
  @CreateDateColumn()
  createdAt: Date;

  @Field(() => Date)
  @UpdateDateColumn()
  updatedAt: Date;
}
