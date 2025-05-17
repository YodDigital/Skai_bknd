import pandas as pd
from sqlalchemy import create_engine
import time

# Log the start time
start_time = time.time()

# Step 1: Load the CSV data into a DataFrame
csv_file_path = '/home/raph/Documents/Skai_bknd/workspace/user_11/raphy_20250516131441.csv'
df = pd.read_csv(csv_file_path)

# Log the time taken to load the CSV
print(f"CSV Loaded in {time.time() - start_time:.2f} seconds.")

# Step 2: Data Transformation
# Keep only the relevant columns and handle missing values
df = df[['Age', 'Attrition', 'BusinessTravel', 'DailyRate', 'Department', 'DistanceFromHome',
         'Education', 'EducationField', 'EmployeeCount', 'EmployeeNumber', 'EnvironmentSatisfaction',
         'Gender', 'HourlyRate', 'JobInvolvement', 'JobLevel', 'JobRole', 'JobSatisfaction',
         'MaritalStatus', 'MonthlyIncome', 'MonthlyRate', 'NumCompaniesWorked', 'Over18',
         'OverTime', 'PercentSalaryHike', 'PerformanceRating', 'RelationshipSatisfaction',
         'StandardHours', 'StockOptionLevel', 'TotalWorkingYears', 'TrainingTimesLastYear',
         'WorkLifeBalance', 'YearsAtCompany', 'YearsInCurrentRole', 'YearsSinceLastPromotion',
         'YearsWithCurrManager']]

# Fill missing values where necessary
df['OverTime'].fillna('No', inplace=True)
df['Attrition'].fillna('No', inplace=True)

# Create dimension and fact tables deduplicated
employee_dimensions = df[['EmployeeNumber', 'Age', 'BusinessTravel', 'Department', 'Education', 
                           'EducationField', 'Gender', 'JobRole', 'JobLevel', 'JobInvolvement', 
                           'JobSatisfaction', 'MaritalStatus', 'PerformanceRating', 
                           'RelationshipSatisfaction', 'StandardHours', 'StockOptionLevel', 
                           'WorkLifeBalance', 'PercentSalaryHike']].drop_duplicates()

employee_fact = df[['EmployeeNumber', 'DailyRate', 'DistanceFromHome', 'MonthlyIncome', 
                    'MonthlyRate', 'NumCompaniesWorked', 'TotalWorkingYears', 
                    'TrainingTimesLastYear', 'YearsAtCompany', 'YearsInCurrentRole', 
                    'YearsSinceLastPromotion', 'YearsWithCurrManager', 'OverTime', 'Attrition']]

# Log the transformation time
print(f"Data Transformation Completed in {time.time() - start_time:.2f} seconds.")

# Step 3: Load the Data into SQLite
db_path = '/home/raph/Documents/Skai_bknd/workspace/user_11/database.db'
engine = create_engine(f'sqlite:///{db_path}')

# Creating tables in SQLite
employee_dimensions.to_sql('Employee_Dimension', con=engine, if_exists='replace', index=False)
employee_fact.to_sql('Employee_Fact', con=engine, if_exists='replace', index=False)

# Log the loading time
print(f"Data Loaded to SQLite Database in {time.time() - start_time:.2f} seconds.")
print("ETL Process Completed.")